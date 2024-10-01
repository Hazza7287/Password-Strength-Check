import re
import requests
import hashlib

# Function to check password strength
def check_password_strength(password):
    # Define strength criteria
    length_criteria = len(password) >= 8
    digit_criteria = re.search(r"\d", password) is not None
    uppercase_criteria = re.search(r"[A-Z]", password) is not None
    lowercase_criteria = re.search(r"[a-z]", password) is not None
    symbol_criteria = re.search(r"[!@#$%^&*()_+{}:<>?]", password) is not None

    # Evaluate strength
    strength_score = sum([length_criteria, digit_criteria, uppercase_criteria, lowercase_criteria, symbol_criteria])

    # Determine feedback based on strength score
    if strength_score == 5:
        return "Strong"
    elif 3 <= strength_score < 5:
        return "Moderate"
    else:
        return "Weak"

# Function to check if the password is in a data breach
def check_pwned_password(password):
    # Hash the password using SHA-1 (required by Have I Been Pwned API)
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]

    # Query the Have I Been Pwned API
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    # Check if the password's hash suffix is in the response
    if suffix in response.text:
        return True
    return False

# Function to provide feedback on the password
def provide_feedback(password):
    strength = check_password_strength(password)
    is_pwned = check_pwned_password(password)

    feedback = f"Password strength: {strength}\n"
    
    if is_pwned:
        feedback += "Warning: This password has been found in a data breach!\n"
    else:
        feedback += "Good news: This password has not been found in any known data breaches.\n"

    if strength == "Weak":
        feedback += "Suggestions: Use at least 8 characters, include uppercase, lowercase, digits, and symbols.\n"
    elif strength == "Moderate":
        feedback += "Suggestions: Consider adding more complexity (uppercase, digits, symbols) for better security.\n"
    
    return feedback

# Main function to run the password checker
def main():
    password = input("Enter a password to check its strength: ")
    feedback = provide_feedback(password)
    print(feedback)

if __name__ == "__main__":
    main()
