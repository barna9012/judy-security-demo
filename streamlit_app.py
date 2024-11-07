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
        response = call_api(user_input)
        
        # Display response from API
        if "error" in response:
            st.error(f"Error: {response['error']}")
        else:
            st.write("Response from API:")
            # Display result_1 and result_2 if they exist in the response
            result_1 = response.get("result_1", "No 'result_1' key found in response")
            result_2 = response.get("result_2", "No 'result_2' key found in response")
            
            st.write("Result 1:")
            st.json(result_1)
            
            st.write("Result 2:")
            st.json(result_2)
    else:
        st.warning("Please enter a question before sending.")
