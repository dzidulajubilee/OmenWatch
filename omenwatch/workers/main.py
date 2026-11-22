"""
The two background workers, created once. The app starts and stops them
(app.py's lifespan); "Refresh now" and "Run feed now" call into them.
"""
from omenwatch.core.live import broadcast
from omenwatch.workers.ioc_worker import IocScheduler
from omenwatch.workers.news_worker import Scheduler

news_worker = Scheduler(broadcast)
ioc_worker = IocScheduler()
