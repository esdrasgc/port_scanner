import sys
from PyQt5.QtCore import pyqtSignal, QThread
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QTextEdit, QProgressBar, QCheckBox
)
import socket
from concurrent.futures import ThreadPoolExecutor

# Worker thread for scanning ports
class PortScannerWorker(QThread):
    update_progress = pyqtSignal()
    update_output = pyqtSignal(str)

    def __init__(self, host, port_range, well_known_ports):
        super().__init__()
        self.host = host
        self.port_range = port_range
        self.well_known_ports = well_known_ports

    def run(self):
        start_port, end_port = self.port_range
        results = []

        # Determine the address family (IPv4 or IPv6)
        try:
            addr_info = socket.getaddrinfo(self.host, None)
            af = addr_info[0][0]
        except socket.gaierror:
            self.update_output.emit("Invalid host address")
            return

        # Use ThreadPoolExecutor to scan multiple ports concurrently
        with ThreadPoolExecutor(max_workers=100) as executor:
            for port in range(start_port, end_port + 1):
                executor.submit(self.scan_port, af, port, results)

        output = self.display_results(results)
        self.update_output.emit(output)

    def scan_port(self, af, port, results):
        try:
            with socket.socket(af, socket.SOCK_STREAM) as s:
                s.settimeout(0.2)  # Reduced timeout for faster scanning
                result = s.connect_ex((self.host, port))
                if result == 0:
                    # Try to get the service name
                    try:
                        service = socket.getservbyport(port, 'tcp')
                    except OSError:
                        service = 'Unknown'
                    results.append((port, 'Open', service))
                else:
                    results.append((port, 'Closed'))
        except Exception as e:
            results.append((port, 'Error'))
        finally:
            self.update_progress.emit()

    def display_results(self, results):
        output = []
        for port, status, *service in sorted(results):
            if status == 'Open':  # Only include open ports
                service_name = service[0] if service else 'Unknown'
                output.append(f'Port {port}: {status} - Service: {service_name}')
        return '\n'.join(output)

# Function to load well-known ports from the file
def load_well_known_ports(file_path):
    well_known_ports = {}
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith('#') or line.strip() == '':
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                port = int(parts[1])
                service = parts[2] if len(parts) > 2 else 'Unknown'
                well_known_ports[port] = service
    return well_known_ports

# Main GUI class with PyQt5
class PortScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.well_known_ports = load_well_known_ports('./well-known-port-numbers.txt')
        self.worker = None

    def initUI(self):
        self.setWindowTitle('Port Scanner')

        layout = QVBoxLayout()

        self.host_label = QLabel('Hostname or IP:')
        self.host_input = QLineEdit()

        self.port_range_label = QLabel('Port Range (start-end):')
        self.port_range_input = QLineEdit()

        self.well_known_checkbox = QCheckBox('Scan All Well-Known Ports (0-1023)')
        self.well_known_checkbox.stateChanged.connect(self.toggle_well_known)

        self.scan_button = QPushButton('Scan')
        self.scan_button.clicked.connect(self.scan_ports)

        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)

        layout.addWidget(self.host_label)
        layout.addWidget(self.host_input)
        layout.addWidget(self.port_range_label)
        layout.addWidget(self.port_range_input)
        layout.addWidget(self.well_known_checkbox)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.output_area)

        self.setLayout(layout)

    def toggle_well_known(self):
        if self.well_known_checkbox.isChecked():
            self.port_range_input.setDisabled(True)
            self.port_range_input.setText('0-1023')
        else:
            self.port_range_input.setDisabled(False)
            self.port_range_input.clear()

    def update_progress(self):
        current_value = self.progress_bar.value()
        self.progress_bar.setValue(current_value + 1)

    def update_output(self, output):
        self.output_area.setText(output)

    def scan_ports(self):
        host = self.host_input.text()
        port_range = self.port_range_input.text()

        if '-' in port_range:
            start_port, end_port = map(int, port_range.split('-'))
            self.progress_bar.setMaximum(end_port - start_port + 1)
            self.progress_bar.setValue(0)

            self.worker = PortScannerWorker(host, (start_port, end_port), self.well_known_ports)
            self.worker.update_progress.connect(self.update_progress)
            self.worker.update_output.connect(self.update_output)
            self.worker.start()
        else:
            self.output_area.setText('Please enter a valid port range (e.g., 20-80).')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PortScannerApp()
    ex.show()
    sys.exit(app.exec_())
