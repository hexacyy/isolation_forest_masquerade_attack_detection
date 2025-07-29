import logging
import sys

def setup_logging():
    logging.basicConfig(
        level=logging.DEBUG,  # Change to INFO or WARNING in production
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout)  # log to console (or app.log if redirected)
        ]
    )