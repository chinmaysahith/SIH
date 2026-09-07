import logging
from typing import Optional, Tuple
import redis
from rq import Queue

from app.config import QUEUE_NAME, REDIS_URL

logger = logging.getLogger("email_forensics.queue")


def get_redis_connection(url: Optional[str] = None) -> redis.Redis:
    """Creates a Redis client from configured URL."""
    redis_url = url or REDIS_URL
    return redis.from_url(
        redis_url,
        socket_connect_timeout=3,
        socket_timeout=5,
    )


def get_queue(connection: Optional[redis.Redis] = None) -> Queue:
    """Returns the designated RQ queue."""
    conn = connection or get_redis_connection()
    return Queue(QUEUE_NAME, connection=conn)


def enqueue_case_analysis(
    case_id: str,
    connection: Optional[redis.Redis] = None,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Enqueues a case for background processing in RQ.

    Returns:
        (success: bool, job_id: Optional[str], error_message: Optional[str])
    """
    try:
        q = get_queue(connection=connection)
        # Enqueue background placeholder job
        # Note: target function is imported via dotted string path so worker imports it cleanly
        job = q.enqueue(
            "app.jobs.process_case.process_case",
            args=(case_id,),
            job_timeout="10m",
            result_ttl=86400,
        )
        logger.info("JOB ENQUEUED: case_id=%s, job_id=%s, queue=%s", case_id, job.id, QUEUE_NAME)
        return True, job.id, None
    except Exception as exc:
        logger.warning(
            "JOB ENQUEUE FAILED: case_id=%s, queue=%s, error=%s",
            case_id,
            QUEUE_NAME,
            str(exc),
        )
        return False, None, f"Redis queue unavailable: {str(exc)}"
