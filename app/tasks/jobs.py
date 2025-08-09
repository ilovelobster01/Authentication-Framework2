import time

def echo(message: str, delay: float = 0.0):
    if delay:
        time.sleep(delay)
    return {"echo": message, "delay": delay}

