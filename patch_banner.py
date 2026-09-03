with open("dashboard/app.py", "r") as f:
    app_code = f.read()

banner = """
if check_for_updates():
    st.markdown("<div style='background-color: #ff4b4b; padding: 15px; border-radius: 8px; color: white; font-weight: bold; text-align: center; margin-bottom: 25px; border: 1px solid #ff0000;'>UPDATE AVAILABLE: Your local copy of NeuralSOC is outdated. Please run 'git pull origin main' in your terminal to sync with the latest AI models and security patches.</div>", unsafe_allow_html=True)
"""

target = "# Top bar layout - Professional Header"
if target in app_code:
    app_code = app_code.replace(target, banner + "\n" + target)

with open("dashboard/app.py", "w") as f:
    f.write(app_code)
