# command.py
import private
import random
from functions import process_eml_file, analyze_url, analyze_message_with_gpt, safe_send_message
from telegram import Update,ReplyKeyboardMarkup 
from telegram import Update, ReplyKeyboardMarkup, ReplyKeyboardRemove
from telegram.ext import CommandHandler, MessageHandler, filters, ContextTypes, ConversationHandler


from telegram.ext import ContextTypes
import requests
import os
from urllib.parse import urlparse
# State constants for conversation handlers
WAITING_FOR_URL = 1
WAITING_FOR_MESSAGE = 1
QUIZ_STATE = 0
quiz_index = 0  # Index to control the current quiz question

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /start is issued."""
    user = update.effective_user
    # Creating a custom keyboard with the /help button
    custom_keyboard = [['/help']]
    reply_markup = ReplyKeyboardMarkup(custom_keyboard)
    # Welcome message and instructions for the user
    welcome_message = (
        f"Hi {user.first_name}! I'm a bot designed to help you understand and identify phishing.\n"
        "I can analyze .eml files for suspicious content, provide tips on avoiding phishing, "
        "and much more. For a list of commands and how to use them, please press the /help button."
    )
    await update.message.reply_text(welcome_message, reply_markup=reply_markup)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /help is issued."""
    help_text = (
        "Use these commands to learn and protect yourself from phishing:\n\n"
        "/email - Send an .eml file to be analyzed for phishing threats.\n"
        "/tutorial - Tutorial of how to send a .eml file on iOS devices.\n"
        "/tips - Get quick tips to avoid phishing.\n"
        "/examples - See phishing examples to recognize them.\n"
        "/whatIsPhishing - Understand what phishing is.\n"
        "/askGPT - Ask ChatGPT a question about Phishing.\n"
        "/analyzeUrl - Send a URL to check if it's safe.\n"
        "/quizPhishing - Take a quiz to test your phishing spotting skills."
    )
    await update.message.reply_text(help_text)


# Handler for the command /email
async def email_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text('Please, send file .eml to analize.')

async def decision_handler(update, context):
    respuesta = update.message.text
    if respuesta.lower() == "continuar":
        await update.message.reply_text('Please, send a .eml file to analyze.')
    elif respuesta.lower() == "finalizar":
        custom_keyboard = [['/tips', '/examples'], ['/whatIsPhishing', '/askGPT'], ['/analyzeUrl', '/quizPhishing']]
        reply_markup = ReplyKeyboardMarkup(custom_keyboard, resize_keyboard=True)
        await update.message.reply_text('Elige una opción:', reply_markup=reply_markup)



# Function to handle received documents
async def document_handler(update, context):
    document = update.message.document
    print("Tipo MIME recibido:", document.mime_type)
    file_extension = document.file_name.split('.')[-1].lower()
    if document.mime_type == 'message/rfc822' or file_extension == 'eml':  # Verifica si el documento es un archivo .eml
        await update.message.reply_text("File .eml recived, processing... this will take a moment so be patient.")
        print("File .eml recived, processing... this will take a moment so be patient.")
        
        # Download the file
        file = await context.bot.get_file(document.file_id)
        """print(f"oli{file.file_path}")"""
        carpeta_destino = './emails'
        
        os.makedirs(carpeta_destino, exist_ok=True)
        parsed_url = urlparse(file.file_path)
        path = parsed_url.path
        file_name = os.path.basename(path)
        ruta_completa = os.path.join(carpeta_destino, file_name)
        respuesta = requests.get(file.file_path)
        if respuesta.status_code == 200:
             # Write the binary content of the response to the file
            with open(ruta_completa, 'wb') as archivo:
                # Escribe el contenido binario de la respuesta en el archivo
                archivo.write(respuesta.content)
            print(f'Archivo descargado con éxito y guardado en {ruta_completa}')
        else:
            print('Error al descargar el archivo:', respuesta.status_code)
        # Process the .eml file here
        info_message = await process_eml_file(ruta_completa)
        chat_id = update.message.chat_id
        await safe_send_message(context, chat_id, info_message)
        #await update.message.reply_text(info_message)
        
        # Ask the user if they want to continue or finish
        custom_keyboard = [['Continuar', 'Finalizar']]
        reply_markup = ReplyKeyboardMarkup(custom_keyboard, one_time_keyboard=True, resize_keyboard=True)
        await update.message.reply_text("¿Deseas enviar otro archivo .eml o finalizar?", reply_markup=reply_markup)
    else:
        await update.message.reply_text("Por favor, envía un archivo .eml.")
        

    
async def tutorial(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # ID of the video file or direct URL
    video_id = './tutorial/tutorial.MP4'
    
    # Send the video to the user
    await context.bot.send_video(chat_id=update.effective_chat.id, video=video_id)
    
async def examples(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    images_directory = './examples/'
    all_images = [f for f in os.listdir(images_directory) if f.endswith('.jpg')]
    
    # Select a random image from the list
    if all_images:  # Check if there are any images
        selected_image = random.choice(all_images)
        image_path = os.path.join(images_directory, selected_image)
        
        # Send the selected image to the user
        await context.bot.send_photo(chat_id=update.effective_chat.id, photo=open(image_path, 'rb'))
    else:
        # Send a message if no images are available
        await update.message.reply_text("No examples available at the moment.")

async def what_is_phishing(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    phishing_explanation = (
        "Phishing is a cybercrime in which a target or targets are contacted by email, telephone or text message by "
        "someone posing as a legitimate institution to lure individuals into providing sensitive data such as "
        "personally identifiable information, banking and credit card details, and passwords.\n\n"
        "The information is then used to access important accounts and can result in identity theft and financial loss."
    )
    await update.message.reply_text(phishing_explanation)


async def tips(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    tips_text = (
        "💡 *Anti-Phishing Tips* 💡\n\n"
        "- *Suspicious Email Addresses, Links, and Domain Names*: Check for slight anomalies in email addresses that seem almost correct but have variations, links that lead to unknown addresses when hovered over, and domain names that mimic real ones with minor mistakes.\n\n"
        
        "- *Threats or Sense of Urgency*: Phishing attacks often create a sense of urgency or threat, like account compromise, pushing you to reveal personal information or act quickly without verifying the source.\n\n"
        
        "- *Grammar and Spelling Errors*: Phishing emails may contain significant grammatical and spelling errors not expected in communications from trustworthy or professional entities.\n\n"
        
        "- *Suspicious Attachments*: Question attachments that are not mentioned or do not correspond with the body of the message, especially if the email seems legitimate but the attachment is irrelevant or unexpected.\n\n"
        
        "- *Requests for Personal Information*: Be skeptical of emails asking for login credentials, payment information, or sensitive data, as legitimate companies generally do not request this information via email."
    )
    # Send the tips message
    await update.message.reply_text(tips_text, parse_mode='Markdown')
        

quiz_questions = [
    {
        "question": "What is phishing?",
        "options": ["A) A sport fishing technique", "B) A type of malware", "C) An attack to steal sensitive info by deception", "D) A new security feature in web browsers"],
        "answer": "C"
    },
    {
        "question": "What is a common sign of a phishing email?",
        "options": ["A) Using a personalized greeting", "B) Perfect grammar and spelling", "C) An offer that seems too good to be true", "D) A sender with a legitimate email domain"],
        "answer": "C"
    },
    {
        "question": "What should you do if you receive a phishing email?",
        "options": ["A) Reply to the sender asking for more information", "B) Click on links to verify their authenticity", "C) Ignore it and delete it immediately", "D) Share it with all your contacts to warn them"],
        "answer": "C"
    }
]


async def start_quiz(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    global quiz_index
    quiz_index = 0  # Reset the index for each new player
    question = quiz_questions[quiz_index]["question"]
    options_text = "\n".join(quiz_questions[quiz_index]["options"])
    
    # Send the question and options as text
    await update.message.reply_text(f"{question}\n\n{options_text}")
    
    reply_keyboard = [['A', 'B', 'C', 'D']]
    reply_markup = ReplyKeyboardMarkup(reply_keyboard, one_time_keyboard=True, resize_keyboard=True)
    
    # Ask the user to select an option
    await update.message.reply_text("Por favor, selecciona una opción:", reply_markup=reply_markup)
    
    return QUIZ_STATE


async def handle_quiz_answer(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    global quiz_index
    answer = update.message.text[0] # Assume the answer is the first letter
    correct_answer = quiz_questions[quiz_index]["answer"]

    # Evaluate the answer for the last question
    if quiz_index == len(quiz_questions) - 1:  # If it's the last question
        if answer.upper() == correct_answer:
            await update.message.reply_text("Correct! 🎉", reply_markup=ReplyKeyboardRemove())
        else:
            await update.message.reply_text("That's not correct. 😢", reply_markup=ReplyKeyboardRemove())
        
        # Send the quiz finished message after evaluating the last question
        await update.message.reply_text("Quiz finished! Thanks for participating.")
        
        return ConversationHandler.END

    # Processing if it's not the last question
    if answer.upper() == correct_answer:
        response_message = "Correct! 🎉"
    else:
        response_message = "That's not correct. 😢"
    
    quiz_index += 1  # Move to the next question index
    
    if quiz_index < len(quiz_questions):  # Check if there are more questions
        question = quiz_questions[quiz_index]["question"]
        options_text = "\n".join(quiz_questions[quiz_index]["options"])
        reply_keyboard = [['A', 'B', 'C', 'D']]
        reply_markup = ReplyKeyboardMarkup(reply_keyboard, one_time_keyboard=True, resize_keyboard=True)
        
        await update.message.reply_text(response_message, reply_markup=ReplyKeyboardRemove())  # Remove the previous keyboard
        await update.message.reply_text(f"{question}\n\n{options_text}", reply_markup=reply_markup)  # Send new question and keyboard
        
        return QUIZ_STATE

    return ConversationHandler.END
   
async def start_analyze_url(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    # Request the user to send the URL for analysis
    await update.message.reply_text("Please send the URL you want to analyze, if you send 2 only the last one will be analyze.")
    return WAITING_FOR_URL

async def analyze_url_received(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    url = update.message.text.strip()
    result = await analyze_url(url, private.api_key_urlscan)
    if result and 'uuid' in result:
        scan_id = result['uuid']
        message = f"URL submitted for analysis. Check the result here: https://urlscan.io/result/{scan_id}/"
    else:
        if 'errors' in result:
            error_detail = result['errors'][0]['detail']
            message = f"Failed to analyze the URL. Error: {error_detail}"
        else:
            message = "Failed to analyze the URL. Please try again."
    
    await update.message.reply_text(message)
    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    # Send a message indicating the operation is cancelled
    await update.message.reply_text('Operation cancelled.')
    return ConversationHandler.END

async def ask_to_chat_gpt(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    # Request the user to send the question for ChatGPT
    await update.message.reply_text("Please send the question you want to ask to ChatGPT.")
    return WAITING_FOR_MESSAGE

async def analyze_question_gpt(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    message = update.message.text.strip()
    api_key_gpt = private.chatGPT_api  

    analysis_result = await analyze_message_with_gpt(message, api_key_gpt)
    print(analysis_result)
    if analysis_result:
        await update.message.reply_text(f"GPT Response: {analysis_result}")
    else:
        await update.message.reply_text("Failed connection to GPT. Please try again. /askGPT")
    
    return ConversationHandler.END 
