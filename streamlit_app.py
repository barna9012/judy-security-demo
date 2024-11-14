import streamlit as st
import requests

# Function to call your API
def call_api(user_input):
    api_url = "http://dev-judy-security-demo-alb-1215923742.eu-central-1.elb.amazonaws.com/vulnerabilities"  # Replace with your actual API endpoint
    headers = {
        "Content-Type": "application/json"
    }
    payload = {"description": user_input}
    
    try:
        response = requests.post(api_url, json=payload, headers=headers)
        response.raise_for_status()  # Raises an HTTPError for bad responses

        # Check if the response is JSON
        if response.headers.get("Content-Type") == "application/json":
            return response.json()
        else:
            return {"error": "Unexpected response format from API. Expected JSON."}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

# Streamlit UI
st.title("API Query Tool")

# User input form
user_input = st.text_input("Enter your question:")

# Add a "Send" button
if st.button("Send"):
    if user_input:
        # Call API and get response
        #response = call_api(user_input)

        # Test
        response = {
            "message": "Input'give me some details about CVE-2024-51567 vulnerability' created successfully!",
            "category": "CVE_number",
            "result": {
                "CVEs": [
                    {
                        "cve_id": "CVE-2024-51567",
                        "affected_components": [
                            {
                                "vendor": "CyberPanel",
                                "product": "CyberPanel",
                                "versions": {
                                    "affected_range": " - 2.3.8",
                                    "fixed_version": "2.3.9"
                                }
                            }
                        ],
                        "technical_details": {
                            "attack_vector": "Remote Code Execution via authentication bypass and shell metacharacters injection in /dataBases/upgrademysqlstatus endpoint",
                            "impact": "Allows remote attackers to execute arbitrary commands on the system"
                        },
                        "mitigation": {
                            "fix_details": "Upgrade to CyberPanel version 2.3.9 or later",
                            "workarounds": "Restrict access to the /dataBases/upgrademysqlstatus endpoint until a fix is applied",
                            "upgrade_path": "Upgrade to the latest stable version of CyberPanel from the official sources"
                        },
                        "Detailed summary": "This vulnerability in the upgrademysqlstatus function of CyberPanel before version 2.3.9 allows remote attackers to bypass authentication and execute arbitrary commands by injecting shell metacharacters in the statusfile property of the /dataBases/upgrademysqlstatus endpoint. The vulnerability was actively exploited in the wild in October 2024. Affected versions include all releases up to 2.3.8. Users should upgrade to version 2.3.9 or later from official sources to remediate this issue.",
                        "published": "2024-10-29T23:15:04.307",
                        "lastModified": "2024-11-08T21:14:28.807",
                        "description": "upgrademysqlstatus in databases/views.py in CyberPanel (aka Cyber Panel) before 5b08cd6 allows remote attackers to bypass authentication and execute arbitrary commands via /dataBases/upgrademysqlstatus by bypassing secMiddleware (which is only for a POST request) and using shell metacharacters in the statusfile property, as exploited in the wild in October 2024 by PSAUX. Versions through 2.3.6 and (unpatched) 2.3.7 are affected.",
                        "cvss31_score": 9.8,
                        "cvss31_severity": "CRITICAL",
                        "cwe_numbers": [
                            "CWE-306",
                            "CWE-276"
                        ],
                        "references": [
                            "https://cwe.mitre.org/data/definitions/420.html",
                            "https://cwe.mitre.org/data/definitions/78.html",
                            "https://cyberpanel.net/KnowledgeBase/home/change-logs/",
                            "https://cyberpanel.net/blog/detials-and-fix-of-recent-security-issue-and-patch-of-cyberpanel",
                            "https://dreyand.rs/code/review/2024/10/27/what-are-my-options-cyberpanel-v236-pre-auth-rce",
                            "https://github.com/usmannasir/cyberpanel/commit/5b08cd6d53f4dbc2107ad9f555122ce8b0996515",
                            "https://www.bleepingcomputer.com/news/security/massive-psaux-ransomware-attack-targets-22-000-cyberpanel-instances/"
                        ],
                        "cisa": {
                            "cveID": "CVE-2024-51567",
                            "vendorProject": "CyberPersons",
                            "product": "CyberPanel",
                            "requiredAction": "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
                            "notes": "https://cyberpanel.net/blog/detials-and-fix-of-recent-security-issue-and-patch-of-cyberpanel ; https://nvd.nist.gov/vuln/detail/CVE-2024-51567",
                            "cisa_references": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                        }
                    }
                ]
            }
        }
        
        # Display response from API
        if "error" in response:
            st.error(f"Error: {response['error']}")
        else:
            st.write("Vulnerability Details:")

            # Extract the CVE data from the response
            cves = response.get("result", {}).get("CVEs", [])
            
            # Display each CVE in a nicely formatted way
            for cve in cves:
                st.subheader(f"CVE ID: {cve.get('cve_id', 'N/A')}")

                st.write("### Additional Information")
                st.write(f"**Published Date:** {cve.get('published', 'N/A')}")
                st.write(f"**Last Modified Date:** {cve.get('lastModified', 'N/A')}")
                st.write(f"**Description:** {cve.get('description', 'N/A')}")
                st.write(f"**CVSS Score:** {cve.get('cvss31_score', 'N/A')} ({cve.get('cvss31_severity', 'N/A')})")

                st.write("### Technical Details")
                technical_details = cve.get("technical_details", {})
                st.write(f"**Attack Vector:** {technical_details.get('attack_vector', 'N/A')}")
                st.write(f"**Impact:** {technical_details.get('impact', 'N/A')}")

                st.write("### CWE Numbers")
                cwe_numbers = ", ".join(cve.get("cwe_numbers", []))
                st.write(cwe_numbers if cwe_numbers else "No CWE numbers available.")
                
                st.write("### Affected Components")
                for component in cve.get("affected_components", []):
                    st.write(f"**Vendor:** {component.get('vendor', 'N/A')}")
                    st.write(f"**Product:** {component.get('product', 'N/A')}")
                    versions = component.get("versions", {})
                    st.write(f"**Affected Range:** {versions.get('affected_range', 'N/A')}")
                    st.write(f"**Fixed Version:** {versions.get('fixed_version', 'N/A')}")
                    st.write("---")

                # Optional: Display CISA details if present
                cisa = cve.get("cisa")
                if cisa:
                    st.write("### CISA Information")
                    st.write(f"**Vendor Project:** {cisa.get('vendorProject', 'N/A')}")
                    st.write(f"**Required Action:** {cisa.get('requiredAction', 'N/A')}")
                    st.write(f"**CISA Notes:** {cisa.get('notes', 'N/A')}")

                st.write("### Mitigation")
                mitigation = cve.get("mitigation", {})
                st.write(f"**Fix Details:** {mitigation.get('fix_details', 'N/A')}")
                st.write(f"**Workarounds:** {mitigation.get('workarounds', 'N/A')}")
                st.write(f"**Upgrade Path:** {mitigation.get('upgrade_path', 'N/A')}")                

                st.write("### Summary")
                st.write(cve.get("Detailed summary", "No summary provided"))
                    
                st.write("### References")
                for reference in cve.get("references", []):
                    st.write(f"- [{reference}]({reference})")

                st.write("---")  # Separator between CVEs
    else:
        st.warning("Please enter a question before sending.")
