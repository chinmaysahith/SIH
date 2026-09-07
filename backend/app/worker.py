import logging
import os
import sys

from rq import SimpleWorker, Worker

from app.config import QUEUE_NAME, REDIS_URL
from app.db.database import init_db
from app.services.queue import get_queue, get_redis_connection

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("email_forensics.worker_service")


def run_worker():
    """Runs the background RQ worker."""
    logger.info("Initializing database tables for worker...")
    init_db()

    logger.info("Connecting worker to Redis at: %s", REDIS_URL)
    conn = get_redis_connection()

    # Ping Redis to fail fast if down
    try:
        conn.ping()
        logger.info("Successfully connected to Redis.")
    except Exception as exc:
        logger.error("Failed to connect to Redis at %s: %s", REDIS_URL, exc)
        sys.exit(1)

    queue = get_queue(connection=conn)
    logger.info("Worker listening on queue: '%s'", QUEUE_NAME)

    # Use SimpleWorker with TimerDeathPenalty on Windows, standard Worker on POSIX
    if os.name == "nt":
        from rq.timeouts import TimerDeathPenalty
        SimpleWorker.death_penalty_class = TimerDeathPenalty
        logger.info("Running on Windows: Using rq.SimpleWorker with TimerDeathPenalty")
        worker = SimpleWorker([queue], connection=conn)
    else:
        logger.info("Running on POSIX: Using standard rq.Worker")
        worker = Worker([queue], connection=conn)

    logger.info("Worker started successfully. Awaiting jobs...")
    worker.work(with_scheduler=False)


if __name__ == "__main__":
    run_worker()
