from flask import Flask, render_template, request, send_file
import subprocess
import os

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('homepage.html')


@app.route('/scan')
def test():
    return render_template('face.html')

@app.route('/homepage/#contact-us')
def con():
    return render_template('homepage.html')



@app.route('/home')
def test1():
    return render_template('homepage.html')


def run_dnsrecon(domain):
    try:
        # Run DNSRecon scan command with the specified domain
        process = subprocess.Popen(['dnsrecon', '-d', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        # Check if there was any error during the execution
        if stderr:
            return f"Error: {stderr.decode('utf-8')}", None  # Return error message

        # Write the output to a file
        output_file = f"{domain}_dnsrecon_output.txt"
        with open(output_file, 'w') as f:
            f.write(stdout.decode('utf-8'))

        return stdout.decode('utf-8'), output_file
    except Exception as e:
        return f"Error: {str(e)}", None


def run_xssstrike_scan(url):
    try:
        # Run XSStrike scan command with the specified URL
        process = subprocess.Popen(['xss-strike', '-u', url], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        # Check if there was any error during the execution
        if stderr:
            return f"Error: {stderr.decode('utf-8')}", None  # Return error message

        # Write the output to a file
        output_file = f"{url}_xssstrike_output.txt"
        with open(output_file, 'w') as f:
            f.write(stdout.decode('utf-8'))

        return stdout.decode('utf-8'), output_file
    except Exception as e:
        return f"Error: {str(e)}", None


# Route to handle XSStrike scan request
@app.route('/xss-scan', methods=['POST'])
def xss_scan():
    url = request.form['domain']
    xss_output, xss_filename = run_xssstrike_scan(url)
    return render_template('xss_output.html', output=xss_output, filename=xss_filename)


@app.route('/dnsrecon-scan', methods=['POST'])
def dnsrecon_scan():
    domain = request.form['domain']
    dnsrecon_output, dnsrecon_filename = run_dnsrecon(domain)
    return render_template('dnsrecon_result.html', output=dnsrecon_output, filename=dnsrecon_filename)


def run_nmap_scan(domain):
    try:
        # Run Nmap scan command with the specified domain
        process = subprocess.Popen(['nmap', '-T5', '-A', '-sVC', domain], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        # Check if there was any error during the execution
        if stderr:
            return f"Error: {stderr.decode('utf-8')}", None  # Return error message

        # Write the output to a file
        output_file = f"{domain}_nmap_output.txt"
        with open(output_file, 'w') as f:
            f.write(stdout.decode('utf-8'))

        return stdout.decode('utf-8'), output_file
    except Exception as e:
        return f"Error: {str(e)}", None


@app.route('/nmap-scan', methods=['POST'])
def nmap_scan():
    domain = request.form['domain']
    nmap_output, nmap_filename = run_nmap_scan(domain)
    return render_template('nmap_result.html', output=nmap_output, filename=nmap_filename)


@app.route('/subdomainscan', methods=['POST'])
def subdomainscan():
    domain = request.form['domain']
    output, filename = run_assetfinder(domain)
    return render_template('all_sub.html', output=output, filename=filename)


def run_assetfinder(domain):
    try:
        process = subprocess.Popen(['assetfinder', '-subs-only', domain], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if stderr:
            return f"Error: {stderr.decode('utf-8')}", None  # Return error message
        output_file = f"{domain}_assetfinder_output.txt"
        with open(output_file, 'w') as f:
            f.write(stdout.decode('utf-8'))
        return stdout.decode('utf-8'), output_file
    except Exception as e:
        return f"Error: {str(e)}", None


def run_httprobe(domain):
    try:
        # Check if the file exists
        filename = f"{domain}_assetfinder_output.txt"
        if not os.path.exists(filename):
            return f"Error: File '{filename}' not found", None

        # Run httprobe command with the specified filename
        process = subprocess.Popen(['cat', filename], stdout=subprocess.PIPE)
        httprobe_process = subprocess.Popen(['httprobe', '-s', '-p', 'https:443'], stdin=process.stdout,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.stdout.close()  # Allow httprobe to receive EOF
        stdout, stderr = httprobe_process.communicate()

        # Check if there was any error during the execution
        if stderr:
            return f"Error: {stderr.decode('utf-8')}", None  # Return error message

        output_file = f"{domain}_httprobe_output.txt"
        with open(output_file, 'w') as f:
            f.write(stdout.decode('utf-8'))
        return stdout.decode('utf-8'), output_file
    except Exception as e:
        return f"Error: {str(e)}", None


@app.route('/see-working-domains', methods=['POST'])
def httprobescan():
    domain = request.form['domain']
    assetfinder_output, assetfinder_filename = run_assetfinder(domain)
    httprobe_output, httprobe_filename = run_httprobe(domain)
    return render_template('working.html', output=httprobe_output, filename=assetfinder_filename,
                           httprobe_filename=httprobe_filename)


import subprocess


def run_nuclei_scan(domain):
    try:
        # Run Nuclei scan command with the specified domain
        process = subprocess.Popen(['timeout', '1m', 'nuclei', '-nc', '-u', domain], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        # Combine standard output and standard error into a single output
        output = stdout.decode('utf-8')

        # Write the output to a file
        output_file = f"{domain}_nuclei_output.txt"
        with open(output_file, 'w') as f:
            f.write(output)

        return output, output_file
    except Exception as e:
        return f"Error: {str(e)}", None


# Route to handle Nuclei scan request
@app.route('/basic-scan', methods=['POST'])
def nuclei_scan():
    domain = request.form['domain']
    nuclei_output, nuclei_filename = run_nuclei_scan(domain)
    return render_template('nuclei_result.html', output=nuclei_output, filename=nuclei_filename)


@app.route('/download/<path:filename>')
def download_file(filename):
    return send_file(filename, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
