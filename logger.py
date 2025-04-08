import logging
import os
from datetime import datetime

def setup_logger():
    """Configure logging for the penetration testing tool"""
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    log_file = f"logs/pentest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )