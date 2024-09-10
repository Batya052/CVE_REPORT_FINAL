import time
from logging import error, exception
from flask import Flask, request, render_template
import requests
import webbrowser
from bs4 import BeautifulSoup
import datetime
import pandas as pd
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options
from lxml.doctestcompare import strip
app = Flask(__name__)

#Route for the input form
@app.route('/')
def form():
    return render_template('form.html')


#Route to handle form submission and display results
@app.route('/result', methods=['POST'])
def result():
    #Sabina <
    cve_id = request.form['cve_id'].strip().upper()  # Convert to uppercase for case-insensitive processing

    #Validate the CVE-ID format (CVE-YYYY-NNNNN)
    if (not cve_id.startswith("CVE-")  or len(cve_id.split('-')) != 3):
        return render_template('form.html' , error="Invalid CVE-ID format. Please enter a valid CVE-ID.")

    _, year, number = cve_id.split('-')  #if validation check passed code will split cve_id into 3 parts

    #Validate the year
    try:
        year = int(year)
        current_year = datetime.date.today().year   #Current year
        if year < 1999 or year > current_year:
            return render_template('form.html', error=f"Invalid CVE-ID year. Try between 1999 and {current_year}.")
    except ValueError:
        return render_template('form.html', error="Invalid year format. Year must only contain digits.")

    #Validate the number part
    if len(number) < 4:
        return render_template('form.html', error="Invalid CVE-ID number. The numeric part must be 4 or more digits.")
    elif not number.isnumeric():
        return render_template('form.html' , error = "Invalid number format. Number must only contain digits.")

    #If all zeros
    if all(c == '0' for c in number):
        return render_template('form.html', error="Invalid CVE-ID. The numeric part cannot be all zeros.")

    cve_data = {}   #process information after validation

    #  >>>> Sabina
    alert_message = None



    #Nist soup
    url_nist = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
    response_nist = requests.get(url_nist)
    soup_nist = BeautifulSoup(response_nist.text, "lxml")

    #Sabina <<<<<
    #Check if CVE exists or not
    if response_nist.status_code == 200:
        not_found_message_div = soup_nist.find('div', class_='bs-callout')
        if not_found_message_div:
            not_found_message = not_found_message_div.find('h2')
            if not_found_message and 'CVE ID Not Found' in not_found_message.text:
                return render_template('form.html' , error = f"{cve_id} not exists")

    #Check if alert box exist or not(Rejected,Modified,Awaiting Analysis)
    if response_nist.status_code == 200:
        # Find the alert container
        alert_container = soup_nist.find("div", {"data-testid": "vuln-warning-alert-container"})
        if alert_container:
            alert_type = None
            if 'Rejected' in alert_container.text:
                alert_type = 'Rejected'
            elif 'Awaiting Analysis' in alert_container.text:
                alert_type = 'Awaiting Analysis'
            elif 'Modified' in alert_container.text:
                alert_type = 'Modified'

            if alert_type:
                alert_message = {
                    'type': alert_type,
                    'header': alert_container.find("strong").text.strip(),
                    'description': alert_container.find("p").text.strip()
                }

    # >>>>>>> Sabina
    #INCIBE-CERT soup
    url_incibe = f"https://www.incibe.es/index.php/en/incibe-cert/early-warning/vulnerabilities/{cve_id}"
    response_incibe = requests.get(url_incibe)
    soup_incibe = BeautifulSoup(response_incibe.content, 'html.parser')

    #Exploit-DB soup  ###
    # Configure Selenium to use Chrome in headless mode
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--disable-gpu')  # To avoid issues with GPU

    # Initialize WebDriver
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    url_exploitdb = f"https://www.exploit-db.com/search?cve={year}-{number}"
    driver.get(url_exploitdb)
    time.sleep(3)
    soup_exploitdb = BeautifulSoup(driver.page_source,"lxml")

    ###


    #Scrape NVD description
    try:
        description = soup_nist.find('p', {'data-testid': 'vuln-description'}).get_text(strip=True)
        cve_data['description'] = description
    except Exception as e:
        cve_data['description'] = f"Error fetching data from NVD: {e}"

    #Scrape INCIBE-CERT severity
    try:
        severity_div = soup_incibe.find('div', class_='field-row field-vulnerability-type')
        if severity_div:
            severity = severity_div.find('div', class_='date float-right').get_text(strip=True)
        else:
            severity = "Severity not found"
    except Exception as e:
        cve_data['severity'] = f"Error fetching severity from INCIBE: {e}"
    cve_data['severity'] = severity

    #Scrape INCIBE-CERT publication date
    try:
        pub_date_div = soup_incibe.find('div', class_='field-row field-vulnerability-published')
        if pub_date_div:
            pub_date = pub_date_div.find('div', class_='date float-right').get_text(strip=True)
        else:
            pub_date = "Publication date not found"
    except Exception as e:
        cve_data['publication_date'] = f"Error fetching publication date from INCIBE: {e}"
    cve_data['publication_date'] = pub_date


    #Scrapte NVD CVSS4.0 critically score
    try:
        critically_score4 = soup_nist.find("a", {"id" : "Cvss4NistCalculatorAnchor"})
        if critically_score4:
            critically_score4 = critically_score4.text
        else:
            critically_score4 = f"N/A"
        cve_data['criticality_score4'] = f"CVSS Version 4.0 : {critically_score4} "
    except exception as e:
        cve_data['criticality_score4'] = f"Error fetching data from NVD {e}"

    #Scrapte NVD CVSS3.x critically score
    try:
        critically_score3 = soup_nist.find("a", {"id" : "Cvss3NistCalculatorAnchor"}).text
        cve_data['criticality_score3'] = f"CVSS Version 3.x : {critically_score3} "
    except:
        try:
            critically_score3 = soup_nist.find("a", {"id" : "Cvss3CnaCalculatorAnchor"}).text
            cve_data['criticality_score3'] = f"CVSS Version 3.x : {critically_score3} "
        except:
            try:
                critically_score3 = soup_nist.find("a", {"id": "Cvss3AdpCalculatorAnchor"}).text
                cve_data['criticality_score3'] = f"CVSS Version 3.x : {critically_score3} "
            except:
                critically_score3 = f"N/A"
                cve_data['criticality_score3'] = f"CVSS Version 3.x : {critically_score3} "

    #Scrapte NVD CVSS2.0 critically score
    try:
        critically_score2 = soup_nist.find("a", {"id" : "Cvss2CalculatorAnchor"})
        if critically_score2:
            critically_score2 = critically_score2.text
        else:
            critically_score2 = f"N/A"
        cve_data['criticality_score2'] = f"CVSS Version 2.0 : {critically_score2} "
    except Exception as e:
        cve_data['criticality_score2'] = f"Error fetching data from NVD {e}"


    #Scrape NVD CVSS4.0 vector
    try:
        vector4 = soup_nist.find("span", {"data-testid" : "vuln-cvss4-nist-vector"})
        if vector4:
            vector4 = vector4.text
        else:
            vector4 = f"NVD assessment not yet provided."
        cve_data['vector4'] = f"Vector: CVSS:4.0 {vector4} "
    except exception as e:
        cve_data['vector4'] = f"Error fetching data from NVD {e}"

    #Scrape NVD CVSS3.x vector
    try:
        vector3 = soup_nist.find("span", {"data-testid": "vuln-cvss3-nist-vector"}).text
        cve_data['vector3'] = f"Vector: {vector3} "
    except:
        try:
            vector3 = soup_nist.find("span", {"data-testid": "vuln-cvss3-cna-vector"}).text
            cve_data['vector3'] = f"Vector: {vector3} "
        except:
            try:
                vector3 = soup_nist.find("span", {"data-testid": "vuln-cvss3-adp-vector"}).text
                cve_data['vector3'] = f"Vector: {vector3} "
            except:
                vector3 = f"NVD assessment not yet provided."
                cve_data['vector3'] = f"Vector CVSS:3.x  {vector3} "

    #Scrape NVD CVSS2.0 vector
    try:
        vector2 = soup_nist.find("span", {"data-testid" : "vuln-cvss2-panel-vector"})
        if vector2:
            vector2 = vector2.text
        else:
            vector2 = f"NVD assessment not yet provided."
        cve_data['vector2'] = f"Vector: CVSS:2.0 {vector2} "
    except exception as e:
        cve_data['vector2'] = f"Error fetching data from NVD {e}"


    #Scrape hyperlinks and resources table from NIST
    table_nist = soup_nist.find("table", {"data-testid" : "vuln-hyperlinks-table"})
    #Initialize lists to store data
    hyperlinks = []
    resources = []

    #Extract table rows
    for row in table_nist.find('tbody').find_all('tr'):
        # Extract hyperlink
        link_td = row.find('td', {'data-testid': lambda x: x and x.startswith('vuln-hyperlinks-link-')})
        if link_td:
            hyperlink = link_td.find('a')['href']

            # Check the status code of the link   #Orkhan
            try:
                response = requests.head(hyperlink, allow_redirects=True)
                if response.status_code == 200:
                    hyperlinks.append(hyperlink)

                    # Extract resources if the status code is 200
                    resource_td = row.find('td',
                                           {'data-testid': lambda x: x and x.startswith('vuln-hyperlinks-resType-')})
                    if resource_td:
                        resource_badges = [badge.text.strip() for badge in
                                           resource_td.find_all('span', {'class': 'badge'})]
                        resources.append(', '.join(resource_badges))
            except requests.RequestException:
                # Handle potential request exceptions (e.g., network issues)
                continue

    #Ensure that the number of hyperlinks and resources match
    if len(hyperlinks) != len(resources):
        raise ValueError("Mismatch between number of hyperlinks and resources")

    #Create a DataFrame
    df = pd.DataFrame({
        'Hyperlink': hyperlinks,
        'Resource': resources
    })

    # Combine hyperlinks and resources into a list of tuples
    hyperlinks_and_resources = list(zip(hyperlinks, resources))

    #Scrape exploits-table from Exploit-DB
    table_exploitdb = soup_exploitdb.find("table" , {'class' : 'table table-striped table-bordered display dataTable no-footer dtr-inline'})

    exploits = []

    # Extract rows from the table (excluding the header row)
    rows = table_exploitdb.find('tbody').find_all('tr')
    for row in rows:
        cols = row.find_all('td')

        # Check if the row has enough columns before proceeding
        if len(cols) >= 7:
                exploit = {
                    'date': cols[0].text.strip(),
                    'download_link': "https://www.exploit-db.com" + cols[1].find('a')['href'] if cols[1].find(
                        'a') else '',
                    'verified': 'Yes' if cols[3].find('i', {'class': 'mdi-check'}) else 'No',
                    'title': cols[4].text.strip(),
                    'exploit_link': "https://www.exploit-db.com" + cols[4].find('a')['href'] if cols[4].find(
                        'a') else '',
                    'type': cols[5].text.strip(),
                    'platform': cols[6].text.strip(),
                    'author': cols[7].text.strip() if len(cols) > 7 else ''
                }
                exploits.append(exploit)
        else:
                print(f"Skipping row due to insufficient columns: {cols}")

    # Get the first 5 valid hyperlinks and Open each link in a new tab   Orkhan
    first_five_links = hyperlinks[:5]
    for link in first_five_links:
        webbrowser.open_new_tab(link)

    #Return result.html details
    return render_template('result.html',
                           cve_id=cve_id,
                           alert_message=alert_message,
                           cve_data=cve_data,
                           hyperlinks_and_resources=hyperlinks_and_resources,
                           exploits=exploits      )

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=9000,debug=True)



#https://vulners.com/api/v3/search/id/?id={cve_id}



