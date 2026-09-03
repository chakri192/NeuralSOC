import re

with open("dashboard/app.py", "r") as f:
    app_code = f.read()

update_function = """import subprocess
import requests

@st.cache_data(ttl=3600)
def check_for_updates():
    try:
        local_hash = subprocess.check_output(['git', 'rev-parse', 'HEAD'], stderr=subprocess.DEVNULL).strip().decode('utf-8')
        resp = requests.get("https://api.github.com/repos/chakri192/NeuralSOC/commits/main", timeout=3)
        if resp.status_code == 200:
            remote_hash = resp.json().get('sha', '')
            if remote_hash and local_hash != remote_hash:
                return True
    except Exception:
        pass
    return False

"""

# Insert the function after imports
import_end = app_code.find("st.set_page_config")
if import_end != -1:
    app_code = app_code[:import_end] + update_function + app_code[import_end:]

# Insert the UI banner right after the title
ui_banner = """
    if check_for_updates():
        st.markdown("<div style='background-color: #ff4b4b; padding: 10px; border-radius: 5px; color: white; font-weight: bold; text-align: center; margin-bottom: 20px;'>UPDATE AVAILABLE: Your local copy of NeuralSOC is outdated. Please run `git pull origin main` in your terminal to sync with the latest AI models and security patches.</div>", unsafe_allow_html=True)
"""

title_idx = app_code.find('st.title("Data Diode Cyber Threat Defense")')
if title_idx != -1:
    end_of_title = app_code.find("\n", title_idx)
    app_code = app_code[:end_of_title] + "\n" + ui_banner + app_code[end_of_title:]

with open("dashboard/app.py", "w") as f:
    f.write(app_code)
