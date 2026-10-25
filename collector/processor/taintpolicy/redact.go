package taintpolicy

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"golang.org/x/text/unicode/norm"
)

// --- redaction backstop ---
//
// The backstop runs on EVERY span, whatever the policy says. The policy
// decides violations; the backstop decides whether a raw secret or PII
// pattern is allowed to reach storage (it is not).

const (
	maskPII    = "[PII]"
	maskSecret = "[SECRET]"
	// maskDeep replaces a value nested deeper than maxDepth (fail closed:
	// we refuse to store what we did not scan).
	maskDeep = "[REDACTED]"
	maxDepth = 32
)

// stats is what one byte pass over a string learns. Detectors use it to skip
// their regex when the input cannot possibly match (Go regexps with a
// leading \b or a character class cost about 2us on a short string, so the
// skip is what keeps clean spans cheap).
type stats struct {
	digits   int  // count of ASCII digits
	at       bool // '@' present
	assign   bool // ':' or '=' present
	nonASCII bool
}

func classify(s string) stats {
	var st stats
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			st.digits++
		case c == '@':
			st.at = true
		case c == ':' || c == '=':
			st.assign = true
		case c >= utf8.RuneSelf:
			st.nonASCII = true
		}
	}
	return st
}

type detector struct {
	re   *regexp.Regexp
	mask string
	// group is the submatch to replace (0 = the whole match). Used when a
	// keyword must match but only the value after it is masked.
	group int
	// minDigits: the match needs at least this many ASCII digits.
	minDigits int
	needAt    bool
	needAsgn  bool
	// pre, when set, is a cheap necessary condition (a literal substring).
	pre func(string) bool
	// valid, when set, must accept the matched text (group) for it to be
	// masked. Used for the Luhn check on card numbers.
	valid func(string) bool
}

func (d *detector) mayMatch(s string, st stats) bool {
	if st.digits < d.minDigits || (d.needAt && !st.at) || (d.needAsgn && !st.assign) {
		return false
	}
	return d.pre == nil || d.pre(s)
}

func contains(subs ...string) func(string) bool {
	return func(s string) bool {
		for _, sub := range subs {
			if strings.Contains(s, sub) {
				return true
			}
		}
		return false
	}
}

// containsFold reports whether s contains any of the lower-case ASCII words,
// ignoring ASCII case, without allocating.
func containsFold(words ...string) func(string) bool {
	return func(s string) bool {
		for _, w := range words {
			n := len(w)
			for i := 0; i+n <= len(s); i++ {
				j := 0
				for ; j < n; j++ {
					c := s[i+j]
					if c >= 'A' && c <= 'Z' {
						c += 'a' - 'A'
					}
					if c != w[j] {
						break
					}
				}
				if j == n {
					return true
				}
			}
		}
		return false
	}
}

// Order matters: secrets first, then cards (long digit runs) before the
// shorter SSN / phone shapes, so a card is not half-masked as a phone.
var detectors = []detector{
	// Cloud and SaaS credentials with a fixed prefix.
	{re: regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`), mask: maskSecret},
	{re: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36}`), mask: maskSecret},
	{re: regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`), mask: maskSecret},
	{re: regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`), mask: maskSecret},
	{re: regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`), mask: maskSecret, pre: contains("sk-")},
	{re: regexp.MustCompile(`\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}`), mask: maskSecret, pre: contains("k_live_", "k_test_")},
	{re: regexp.MustCompile(`xox[abposr]-[A-Za-z0-9-]{10,}`), mask: maskSecret},
	{re: regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), mask: maskSecret},
	{re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), mask: maskSecret, pre: contains("eyJ")},
	{re: regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\z)`), mask: maskSecret},
	// Generic key/secret/password assignment: the keyword stays, the value
	// (8+ chars) is masked. "token_count": 5 does not match (\b after token).
	{
		re:   regexp.MustCompile(`(?i)\b(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?key|password|passwd|secret|token)["']?\s*[:=]\s*["']?([A-Za-z0-9_\-./+=~!@#$%^&*]{8,})`),
		mask: maskSecret, group: 1, needAsgn: true,
		pre: containsFold("key", "secret", "token", "passw"),
	},
	{re: regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9_\-.~+/]{16,}=*)`), mask: maskSecret, group: 1, pre: containsFold("bearer")},
	// Payment cards: 13-19 digits, optional single space/dash separators,
	// then a known issuer prefix + length and the Luhn checksum.
	{re: regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`), mask: maskPII, minDigits: 13, valid: validCard},
	// US SSN with dashes, spaces or dots: 3-2-4 is a specific shape.
	{re: regexp.MustCompile(`\b\d{3}[- .]\d{2}[- .]\d{4}\b`), mask: maskPII, minDigits: 9},
	// Bare 9-digit SSN only next to an SSN keyword (see docs: a bare 9-digit
	// rule would mask ordinary IDs, counts and ZIP+4 codes).
	{
		re:   regexp.MustCompile(`(?i)\b(?:ssn|social[ _-]?security(?:[ _-]?(?:number|num|no))?)\b["']?\s*[:=#]?\s*["']?(\d{9})\b`),
		mask: maskPII, group: 1, minDigits: 9, pre: containsFold("ssn", "social"),
	},
	{re: regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`), mask: maskPII, needAt: true},
	{re: regexp.MustCompile(`\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b`), mask: maskPII, minDigits: 10},
}

// maskString returns the redacted form of s and whether anything was masked.
// It does not allocate when nothing matches and s is plain ASCII.
//
// Non-ASCII input is first normalized (zero-width and other format chars
// dropped, NFKC, Unicode dashes and digits folded to ASCII), so that
// fullwidth digits or "234" + U+200B (zero width space) + "-12-1234" cannot dodge the regexes. When
// the normalized form contains a match, the whole value is replaced by the
// masked normalized form. Mapping offsets back through NFKC is error prone
// (one rune can become several and vice versa); storing the normalized text
// only changes how harmless characters look, and only on values that held a
// secret anyway.
func maskString(s string) (string, bool) {
	st := classify(s)
	if st.nonASCII {
		if n, changed := normalize(s); changed {
			if out, hit := applyDetectors(n, classify(n)); hit {
				return out, true
			}
			return s, false
		}
	}
	return applyDetectors(s, st)
}

func applyDetectors(s string, st stats) (string, bool) {
	hit := false
	for i := range detectors {
		d := &detectors[i]
		if !d.mayMatch(s, st) {
			continue
		}
		if !d.re.MatchString(s) {
			continue
		}
		if d.group == 0 && d.valid == nil {
			s = d.re.ReplaceAllLiteralString(s, d.mask)
			hit = true
			continue
		}
		if out, ok := replaceGroup(s, d); ok {
			s, hit = out, true
		}
	}
	return s, hit
}

// replaceGroup masks submatch d.group of every match that d.valid accepts.
func replaceGroup(s string, d *detector) (string, bool) {
	idx := d.re.FindAllStringSubmatchIndex(s, -1)
	var b strings.Builder
	last, changed := 0, false
	for _, m := range idx {
		lo, hi := m[2*d.group], m[2*d.group+1]
		if lo < 0 {
			continue
		}
		if d.valid != nil && !d.valid(s[lo:hi]) {
			continue
		}
		if !changed {
			b.Grow(len(s))
		}
		b.WriteString(s[last:lo])
		b.WriteString(d.mask)
		last, changed = hi, true
	}
	if !changed {
		return s, false
	}
	b.WriteString(s[last:])
	return b.String(), true
}

// --- normalization ---

// normalize folds s into the form the regexes understand. It reports false
// (and allocates nothing) when s is already in that form.
func normalize(s string) (string, bool) {
	if norm.NFKC.IsNormalString(s) && !needsFold(s) {
		return s, false
	}
	n := norm.NFKC.String(s)
	n = strings.Map(foldRune, n)
	return n, n != s
}

func needsFold(s string) bool {
	for _, r := range s {
		if r >= utf8.RuneSelf && foldRune(r) != r {
			return true
		}
	}
	return false
}

// foldRune drops invisible format characters (zero-width space/joiners,
// word joiner, BOM, soft hyphen, bidi controls: Unicode category Cf) and
// maps Unicode dashes, spaces and decimal digits to ASCII.
func foldRune(r rune) rune {
	if r < utf8.RuneSelf {
		return r
	}
	switch {
	case unicode.Is(unicode.Cf, r):
		return -1
	case r == '\u2212' || (r >= '\u2010' && r <= '\u2015') || r == '\ufe63' || r == '\uff0d':
		return '-'
	case unicode.IsSpace(r):
		return ' '
	case unicode.Is(unicode.Nd, r):
		if d, ok := digitValue(r); ok {
			return '0' + d
		}
	}
	return r
}

// digitValue returns the value of a Unicode decimal digit. Every Nd range in
// the Unicode tables is a run of whole 0-9 blocks starting at a zero.
func digitValue(r rune) (rune, bool) {
	for _, rg := range unicode.Nd.R16 {
		if r >= rune(rg.Lo) && r <= rune(rg.Hi) {
			return (r - rune(rg.Lo)) % 10, true
		}
	}
	for _, rg := range unicode.Nd.R32 {
		if r >= rune(rg.Lo) && r <= rune(rg.Hi) {
			return (r - rune(rg.Lo)) % 10, true
		}
	}
	return 0, false
}

// --- payment cards ---

func validCard(m string) bool {
	var buf [19]byte
	n := 0
	for i := 0; i < len(m); i++ {
		c := m[i]
		if c < '0' || c > '9' {
			continue
		}
		if n == len(buf) {
			return false
		}
		buf[n] = c
		n++
	}
	if n < 13 {
		return false
	}
	d := buf[:n]
	return cardPrefixOK(d) && luhn(d)
}

func num(d []byte, k int) int {
	v := 0
	for i := 0; i < k; i++ {
		v = v*10 + int(d[i]-'0')
	}
	return v
}

// cardPrefixOK checks issuer prefix and length. This keeps random 13-19
// digit numbers (unix-ms timestamps start with 1, nanosecond ones are 19
// digits starting with 1) from being masked just because Luhn passed.
func cardPrefixOK(d []byte) bool {
	n := len(d)
	p2, p3, p4 := num(d, 2), num(d, 3), num(d, 4)
	switch {
	case d[0] == '4': // Visa
		return n == 13 || n == 16 || n == 19
	case p2 >= 51 && p2 <= 55, p4 >= 2221 && p4 <= 2720: // Mastercard
		return n == 16
	case p2 == 34 || p2 == 37: // Amex
		return n == 15
	case p4 == 6011, p2 == 65, p3 >= 644 && p3 <= 649: // Discover
		return n >= 16 && n <= 19
	case p4 >= 3528 && p4 <= 3589: // JCB
		return n >= 16 && n <= 19
	case p3 >= 300 && p3 <= 305, p2 == 36, p2 == 38: // Diners
		return n >= 14 && n <= 19
	case p2 == 62: // UnionPay
		return n >= 16 && n <= 19
	}
	return false
}

func luhn(d []byte) bool {
	sum, double := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		v := int(d[i] - '0')
		if double {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
		double = !double
	}
	return sum%10 == 0
}

// --- walking pdata values ---

// maskValue redacts v in place (strings, UTF-8 bytes, and every value nested
// in maps and slices). It returns how many leaf values were masked.
func maskValue(v pcommon.Value, depth int) int {
	switch v.Type() {
	case pcommon.ValueTypeStr:
		if out, hit := maskString(v.Str()); hit {
			v.SetStr(out)
			return 1
		}
	case pcommon.ValueTypeBytes:
		raw := v.Bytes().AsRaw()
		if !utf8.Valid(raw) {
			return 0
		}
		if out, hit := maskString(string(raw)); hit {
			v.SetEmptyBytes().FromRaw([]byte(out))
			return 1
		}
	case pcommon.ValueTypeMap:
		if depth >= maxDepth {
			v.SetStr(maskDeep)
			return 1
		}
		return maskMap(v.Map(), "", depth+1)
	case pcommon.ValueTypeSlice:
		if depth >= maxDepth {
			v.SetStr(maskDeep)
			return 1
		}
		sl := v.Slice()
		n := 0
		for i := 0; i < sl.Len(); i++ {
			n += maskValue(sl.At(i), depth+1)
		}
		return n
	}
	return 0
}

// maskMap redacts every value in m except the one under skipKey ("" skips
// nothing). Values are changed in place; no keys are added or removed, so
// it is safe inside Range.
func maskMap(m pcommon.Map, skipKey string, depth int) int {
	n := 0
	m.Range(func(k string, v pcommon.Value) bool {
		if skipKey != "" && k == skipKey {
			return true
		}
		n += maskValue(v, depth)
		return true
	})
	return n
}
