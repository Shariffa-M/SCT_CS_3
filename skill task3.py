import re
def check_password_strength(password):
    """Assess the strength of a password based on defined criteria."""
    # Define criteria
    min_length = 8
    has_uppercase = bool(re.search(r'[A-Z]', password))
    has_lowercase = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special_char = bool(re.search(r'[!@#$%^&*()_+{}\[\]:;"\'<>,.?/\\|`~]', password))
    is_long_enough = len(password) >= min_length

    # Assess the password
    strength = "Weak"
    if all([has_uppercase, has_lowercase, has_digit, has_special_char, is_long_enough]):
        strength = "Strong"
    elif all([has_uppercase, has_lowercase, has_digit, is_long_enough]):
        strength = "Moderate"
    elif all([has_uppercase, has_lowercase, is_long_enough]):
        strength = "Fair"
    elif is_long_enough:
        strength = "Weak"

    # Generate feedback
    feedback = []
    if not is_long_enough:
        feedback.append(f"Password must be at least {min_length} characters long.")
    if not has_uppercase:
        feedback.append("Password must contain at least one uppercase letter.")
    if not has_lowercase:
        feedback.append("Password must contain at least one lowercase letter.")
    if not has_digit:
        feedback.append("Password must contain at least one digit.")
    if not has_special_char:
        feedback.append("Password must contain at least one special character.")
    
    return strength, feedback

def main():
    print("Welcome to the Password Strength Checker!")

    # Get password input from user
    password = input("Enter the password to check: ")

    # Check password strength
    strength, feedback = check_password_strength(password)

    # Display results
    print(f"Password Strength: {strength}")
    if feedback:
        print("Feedback:")
        for line in feedback:
            print(f" - {line}")

if __name__ == "__main__":
    main()

