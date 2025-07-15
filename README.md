
# College Enquiry Chatbot

This is a comprehensive chatbot application designed specifically for a college enquiry system. Built using Flask and SQLAlchemy, the chatbot leverages Google Cloud Dialogflow for enhanced conversational capabilities.

## Features

- **User Authentication**: Secure login, registration, and password management functionalities.
- **Chatbot Integration**: A responsive chatbot interface to handle common enquiries, created through Google Cloud Dialogflow.
- **Dynamic Responses**: Utilizes a JSON-based response system to handle various queries effectively.
- **Clean and Attractive UI**: Features a chatbot-like design and centered registration forms for a seamless user experience.

## Technical Stack

- **Backend**: Flask and SQLAlchemy for robust database operations and secure token generation.
- **Frontend**: HTML, CSS, and JavaScript for an engaging user interface.
- **Deployment**: Organized directory structure ensuring maintainability and scalability.

## Project Structure

```
cb/
├── __pycache__/
├── bot.py
├── instance/
├── responses.json.json
├── static/
│   ├── css/
│   ├── js/
│   └── images/
├── templates/
│   ├── chat.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── reset_password.html
│   └── base.html
```

## Setup and Installation

1. **Clone the repository:**

    ```sh
    git clone https://github.com/your-username/college-enquiry-chatbot.git
    cd college-enquiry-chatbot/cb
    ```

2. **Create a virtual environment and activate it:**

    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. **Install the dependencies:**

    ```sh
    pip install -r requirements.txt
    ```

4. **Set up the environment variables:**

    Create a `.env` file in the root directory and add the necessary configuration.

    ```sh
    FLASK_APP=bot.py
    FLASK_ENV=development
    SECRET_KEY=your_secret_key
    ```

5. **Run the application:**

    ```sh
    flask run
    ```

## Usage

- **Registration and Login**: Create an account and log in to access the chatbot interface.
- **Chat Interface**: Interact with the chatbot to get answers to common college-related enquiries.

## Contribution

Feel free to fork this repository and contribute by submitting a pull request. Any suggestions or feedback are welcome.


# mini_project
