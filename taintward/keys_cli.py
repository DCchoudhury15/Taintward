"""``python -m taintward.keys_cli``: the taintward-keys command, for images
that copy the package without installing its console scripts (the gateway
image, and so the Helm key rotation CronJob)."""

from taintward.sdk.keys import main

if __name__ == "__main__":
    raise SystemExit(main())
