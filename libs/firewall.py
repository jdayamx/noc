import platform
import subprocess

def check_ufw():
    try:
        output = subprocess.check_output(['which', 'ufw'], stderr=subprocess.STDOUT)
        if output:
            return "ufw is installed"
    except subprocess.CalledProcessError:
        pass
    return None

def check_firewalld():
    try:
        output = subprocess.check_output(['systemctl', 'is-active', '--quiet', 'firewalld'])
        if output.decode('utf-8').strip() == "active":
            version_output = subprocess.check_output(['firewall-cmd', '--version'], stderr=subprocess.STDOUT)
            version = version_output.decode('utf-8').strip()
            return f"firewalld is installed, version: {version}"
    except subprocess.CalledProcessError:
        pass
    return None

def check_iptables():
    try:
        output = subprocess.check_output(['iptables', '--version'], stderr=subprocess.STDOUT)
        version = output.decode('utf-8').strip()
        return f"iptables is installed, version: {version}"
    except subprocess.CalledProcessError:
        pass
    return None

def check_windows_firewall():
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output(['powershell', 'Get-NetFirewallProfile'], stderr=subprocess.STDOUT, timeout=1)
            if "Enabled" in output.decode('utf-8'):
                return "Windows Firewall is installed and active"
        except subprocess.CalledProcessError:
            pass
        except subprocess.TimeoutExpired:
            pass
    return None

def check_firewall():
    firewalls = [
        check_ufw(),
        check_firewalld(),
        check_iptables(),
        #check_windows_firewall(),
    ]
    
    # Збираємо всі знайдені файрволи в список
    installed_firewalls = [fw for fw in firewalls if fw]
    
    if installed_firewalls:
        return ", ".join(installed_firewalls)  # Повертаємо список файрволів з їх версіями
    return "No firewall detected"
