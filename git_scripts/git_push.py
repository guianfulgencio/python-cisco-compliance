"""
Script to git push the CLI running configuration of devices
"""
import git
from datetime import datetime
from rich import print as rprint

# Initialize git repo phhq_device_configurations
repo = git.Repo('phhq_device_configurations')
repo.config_writer().set_value("user", "name", "Guian Fulgencio").release()
repo.config_writer().set_value("user", "email", "gfulgencio@chevron.com").release()
repo.git.add('.')

# Git commit and push
date = datetime.now().strftime("%Y %B %d, %H:%M:%S")
repo.index.commit(f"{date} - change")
repo.git.push()

rprint("✅ Repo has been updated")
