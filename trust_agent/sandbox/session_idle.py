"""Keep the sandbox alive while the operator logs in and starts a Claude session."""
import signal

print('Sandbox ready. Use airlock.py login SESSION, then airlock.py chat SESSION.',flush=True)
signal.pause()
