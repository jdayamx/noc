from flask import Blueprint, flash, redirect, request, session, url_for
from pathlib import Path
import os
import sys
from functools import wraps

python_path = sys.executable
systemd_bp = Blueprint('systemd', __name__)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@systemd_bp.route('/create_noc_service')
@login_required
def create_noc_service():   
    service_path = '/etc/systemd/system/noc.service'

    if Path(service_path).exists():
        flash('Service file already exists.', 'info')
        return redirect(request.referrer or '/')

    try:
        project_dir = Path(__file__).resolve().parent.parent
        script_path = project_dir / 'noc.py'

        content = f"""[Unit]
Description=NOC Service
After=network.target

[Service]
ExecStart={python_path} {script_path}
WorkingDirectory={project_dir}
Restart=always
User=root
Group=root
StandardOutput=append:/var/log/noc.log
StandardError=append:/var/log/noc_error.log

[Install]
WantedBy=multi-user.target
"""

        with open(service_path, 'w') as f:
            f.write(content)
    
        os.system('systemctl daemon-reload')
        os.system('systemctl enable noc.service')

        flash('noc.service created successfully.', 'success')
    except Exception as e:
        flash(f'Failed to create service file: {e}', 'danger')

    return redirect(request.referrer or '/')