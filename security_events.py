#Parent Class
class SecurityEvent:
    def __init__(self, source_ip, severity):
        self.source_ip = source_ip
        self.severity = severity

# Conversions of Risk Levels to Scores
    def get_risk_score(self):
        severity_scores = { "Low": 1, "Medium": 2, "High": 3, "Critical": 4 }
        return severity_scores [self.severity]
        

# States if an event is Critical   
    def is_critical(self):
        if self.severity == "Critical":
            return True
        else:
            return False
    
#Display Information for all event types    
    def show_event(self):
        print("Login Event")
        print(f"Source IP: {self.source_ip}")
        print(f"Severity: {self.severity}")

#Display Suspicous Authentication Information
class LoginEvent(SecurityEvent):
    def __init__(self, source_ip, severity, username):
        super().__init__(source_ip, severity)
        self.username = username

    def show_login(self):
        print("Suspicious Login")
        print(f"Source IP: {self.source_ip}")
        print(f"Severity: {self.severity}")
        print(f"Username: {self.username}")
        
#Represents Malware Related Security Events
class MalwareAlert(SecurityEvent):
    def __init__(self, source_ip, severity, filename):
        super().__init__(source_ip, severity)
        self.filename = filename

    def show_malware(self):
        print("Malware detected")
        print(f"Source IP: {self.source_ip}")
        print(f"Severity: {self.severity}")
        print(f"Filename : {self.filename}")


#Represents Network Related Security Events
class NetworkEvent(SecurityEvent):
    def __init__(self, source_ip, severity, destination_ip, port):
        super().__init__(source_ip,severity)
        self.destination_ip = destination_ip
        self.port = port 
#Check destination port against a list of suspicous ports
    def is_suspicious_port(self):
        suspicious_ports = [4444, 5555, 6666]
        if self.port in suspicious_ports:
            return True
        else:
            return False
    
    def show_network(self):
        print("Suspicious Network Traffic")
        print(f"Source IP: {self.source_ip}")
        print(f"Severity: {self.severity}")
        print(f"Destination IP: {self.destination_ip}")
        print(f"Port: {self.port}")

        