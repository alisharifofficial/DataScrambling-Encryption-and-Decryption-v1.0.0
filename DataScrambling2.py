import pandas as pd
from cryptography.fernet import Fernet
import os

def process_file(input_path, output_path, key, mode='encrypt'):
    """
    Encrypts or decrypts sensitive data in a CSV or Excel file.

    Args:
        input_path (str): The path to the input data file.
        output_path (str): The path to save the processed file.
        key (bytes): The encryption key.
        mode (str): 'encrypt' to encrypt, 'decrypt' to decrypt.

    Returns:
        str: A success or error message.
    """
    try:
        file_extension = os.path.splitext(input_path)[1].lower()
        if file_extension == '.csv':
            df = pd.read_csv(input_path)
        elif file_extension in ['.xls', '.xlsx']:
            df = pd.read_excel(input_path)
        else:
            return "Error: Unsupported file format. Please use a .csv or .xlsx file."
    except FileNotFoundError:
        return f"Error: The file at '{input_path}' was not found."
    except Exception as e:
        return f"Error while reading the file: {e}"

    fernet = Fernet(key)
    processed_df = df.copy()

    sensitive_columns = [
        'name', 'first_name', 'last_name', 'full_name', 'email', 'address',
        'city', 'state', 'zip_code', 'phone_number', 'credit_card', 'ssn',
        'age', 'id'
    ]

    for column in processed_df.columns:
        col_lower = column.lower().strip()
        if col_lower in sensitive_columns:
            if mode == 'encrypt':
                processed_df[column] = processed_df[column].astype(str).apply(lambda x: fernet.encrypt(x.encode()).decode())
            elif mode == 'decrypt':
                try:
                    processed_df[column] = processed_df[column].apply(lambda x: fernet.decrypt(x.encode()).decode())
                except Exception as e:
                    return f"Decryption failed for column '{column}'. Check the key or data integrity: {e}"

    try:
        if file_extension == '.csv':
            processed_df.to_csv(output_path, index=False)
        else:
            processed_df.to_excel(output_path, index=False)
        return f"Success: The file was {'encrypted' if mode == 'encrypt' else 'decrypted'} and saved."
    except Exception as e:
        return f"Error while saving the file: {e}"

def generate_key():
    """Generates a new, secure encryption key."""
    return Fernet.generate_key().decode()