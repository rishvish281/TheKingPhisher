import streamlit as st
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import re
from urllib.parse import urlparse
import whois
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import pandas as pd 
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.utils import shuffle
from nltk.tokenize import RegexpTokenizer  
from sklearn.feature_extraction.text import CountVectorizer  
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
import numpy as np

top_safe_site=['https://www.google.com/','https://www.flipkart.com/','https://www.facebook.com/','https://web.whatsapp.com/','https://www.instagram.com/','https://www.reddit.com/','https://www.amazon.in/']
# Load the dataset (CSV file) containing features and results
def load_dataset(filename):
    dataset = pd.read_csv(filename)
    X = dataset.iloc[:, :-1]  # Features (all columns except the last one)
    y = dataset.iloc[:, -1]   # Result column
    return X, y

from sklearn.preprocessing import StandardScaler
import pandas as pd
from sklearn.utils import shuffle

def preprocess_dataset(X, y):
    # Standardize features
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    # Create separate datasets for each class
    X_positive = X[y == 1]
    X_negative = X[y == 0]

    # Determine the size of the majority class
    max_class_size = max(len(X_positive), len(X_negative))

# Upsample each class to match the size of the majority class
    if len(X_positive) < max_class_size:
        indices = np.random.choice(len(X_positive), max_class_size, replace=True)
        X_positive = X_positive[indices]
    if len(X_negative) < max_class_size:
        indices = np.random.choice(len(X_negative), max_class_size, replace=True)
        X_negative = X_negative[indices]


    # Concatenate the balanced datasets
    X_balanced = pd.concat([pd.DataFrame(X_positive), pd.DataFrame(X_negative)])
    y_balanced = pd.concat([pd.Series([1] * max_class_size), pd.Series([-1] * max_class_size)])

    return X_balanced, y_balanced


st.set_page_config(page_title="Phishing Detector", page_icon=":shield:")

@st.cache_resource
def load_model():
    # Load the dataset (CSV file) containing features and results
    dataset_filename = "phish.csv" 
    X, y = load_dataset(dataset_filename)

    # Preprocess the dataset
    X, y = preprocess_dataset(X, y)

    classifier = KNeighborsClassifier(n_neighbors=3)
    classifier.fit(X, y)
    return classifier
classifier=load_model()

@st.cache_resource
def load_model1():
    df= pd.read_csv("phishing_site_urls.csv")
    df = df.drop_duplicates()
    X_1=df.URL
    y_1=df.Label

    pipeline_ls = make_pipeline(CountVectorizer(tokenizer = RegexpTokenizer(r'[A-Za-z]+').tokenize,stop_words='english'), LogisticRegression(max_iter=507214))
    pipeline_ls.fit(X_1,y_1)
    return pipeline_ls
pipeline_ls=load_model1()

# Function to check SFH (Server Form Handler)
def check_sfh(soup):
    forms = soup.find_all('form')
    
    # If no forms are found, return 1 (safe)
    if not forms:
        return 1

    for form in forms:
        action = form.get('action', '').strip()

        # Check if the action attribute is empty
        if not action or action.startswith(('http://', 'https://')):
            return -1
        

    return 0


# Function to check for Pop-up Windows with Forms
def check_popups(soup):
    popups = soup.find_all('script', text=re.compile(r'alert\('))
    
    for popup in popups:
        if "document.forms" in popup.text:
            return -1  # Popup window contains a form
    
    return 1 

# Function to check SSL final state and issuer's age
def check_ssl_final_state(url):
    try:
        # Check if the URL starts with "https://"
        if not url.startswith("https://"):
            return -1  # HTTPS not present

        # Send an HTTP GET request to the URL with SSL verification
        response = requests.get(url, verify=True)

        # Check if the request was successful
        if response.status_code == 200:
            # Extract the SSL certificate from the response
            cert = x509.load_pem_x509_certificate(response.content, default_backend())

            # Extract the certificate's notBefore date
            not_before = cert.not_valid_before

            # Calculate the age in years
            age_in_years = (datetime.now() - not_before).days / 365

            if age_in_years >= 0.5:
                return 1 
            else:
                return 0 
        else:
            return 0  # SSL not found or other issues
    except Exception as e:
        return 0 # SSL not found or other issues


# Function to check for Request URLs
def check_request_urls(soup):
    total_links = len(soup.find_all('a', href=True))
    external_links = sum(1 for link in soup.find_all('a', href=True) if link['href'].startswith(('http://', 'https://')))

    # Calculate the percentage of request URLs
    if total_links > 0:
        request_url_percentage = (external_links / total_links) * 100
        if request_url_percentage < 22:
            return 1
        elif 22 <= request_url_percentage < 65:
            return 0
    return 0


# Function to check URL length
def check_url_length(url):
    if len(url) < 54:
        return 1
    elif 54<= len(url) <= 75:
        return 0
    return -1

# Function to check Age of Domain
def check_age_of_domain(url):
    try:
        domain = re.search(r'https?://([^/]+)', url).group(1)
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if creation_date and (datetime.now() - creation_date).days < 365:
            return 0
    except Exception as e:
        pass
    return 1

# Function to check the presence of an IP address in the URL
def check_ip_address(url):
    parsed_url = urlparse(url)
    netloc = parsed_url.netloc
    if '/' in netloc:
        netloc = netloc.split('/')[0]
    if ':' in netloc:
        netloc = netloc.split(':')[0]
    if netloc.count('.') >= 4:
        return -1
    return 1

# Function to analyze the website and return features
def analyze_website(url):
    try:
        # Send an HTTP GET request to the URL
        response = requests.get(url)

        # Check if the request was successful
        if response.status_code == 200:
            # Parse the HTML content using BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')

            sfh = check_sfh(soup)
            popups = check_popups(soup)
            ssl = check_ssl_final_state(url)
            request_urls = check_request_urls(soup)
            url_length = check_url_length(url)
            age_of_domain = check_age_of_domain(url)
            ip_address = check_ip_address(url)

            features = [sfh, popups, ssl, request_urls, url_length, age_of_domain, ip_address]

            return features
        else:
            return [-1] * 7  # Return -1 for all features if the request fails
    except Exception as e:
        return [-1] * 7  # Return -1 for all features if an exception occurs


st.title("Phishing Detector")
st.write("Detect suspicious websites to stay safe online")
nav = st.sidebar.radio("Navigation", ["Home", "Detection", "About Us"])
if nav == "Home":

    st.image("phisher.jpg", width=800)
    st.write("Welcome to our phishing detection tool, created by The KingPhishers!")
    hide_st_style = """ <style>#MainMenu {visibility: hidden;}footer {visibility: hidden;} header {visibility: hidden;}</style>"""
    st.markdown(hide_st_style, unsafe_allow_html=True)
    
if nav == "Detection":
    st.header("Website URL Detection")
    hide_st_style = """ <style>#MainMenu {visibility: hidden;}footer {visibility: hidden;} header {visibility: hidden;}</style>"""
    st.markdown(hide_st_style, unsafe_allow_html=True)   

    input_url = st.text_input("Enter the URL to check for phishing")

    if st.button("Check"):
        st.info("Checking... Please wait") 

        safe=False
        for site in top_safe_site:
            if input_url.startswith(site):
                safe=True
                break

        if safe:
            final_prediction="Safe"
        else:
            features = analyze_website(input_url)
            are_all_minus_1 = all(x == -1 for x in features)
            if are_all_minus_1:
                final_prediction=""
            else:
                weight_classifier = 0.7 
                weight_pipeline_ls = 0.3 

                pred_classifier = classifier.predict([features])
                pred_pipeline_ls = pipeline_ls.predict([input_url])
                weighted_average_pred = (weight_classifier * int(pred_classifier[0]) + weight_pipeline_ls * int(pred_pipeline_ls[0])) / (weight_classifier + weight_pipeline_ls)
                threshold = -0.3
        
                if weighted_average_pred > threshold:
                    final_prediction = "Safe"
                else:
                    final_prediction = "Suspicious"
                    no_1=sum(1 for ft in features if ft==1)
                    score=(no_1/7)*100
                    score=round(score,2)


        if final_prediction == "Safe":
            st.success("This website is safe!")
        elif final_prediction == "Suspicious":
            st.warning("This website is suspicious!")
            st.write("The given suspicious website scores "+str(score)+"% in its similarity to genuine domains")
        else:
            st.error("Error: Request Failed | Unable to make a prediction | Please enter valid URL")


if nav == "About Us":
    hide_st_style = """ <style>#MainMenu {visibility: hidden;}footer {visibility: hidden;} header {visibility: hidden;}</style>"""
    st.markdown(hide_st_style, unsafe_allow_html=True)
    st.header("About Us")
    st.write("Kingphishers is a dynamic team of six talented students who have harnessed their collective expertise to create a cutting-edge phishing website detector. With a shared passion for cybersecurity and a commitment to protecting individuals and organizations from online threats, our team has worked tirelessly to develop a sophisticated tool that identifies and safeguards against phishing scams. Through collaboration, innovation, and a dedication to staying one step ahead of cybercriminals, Kingphishers is on a mission to make the digital world a safer place for everyone.")
    st.write("This is our submission for the Smart India Hackathon 2023.")