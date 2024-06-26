import private
import logging

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ConversationHandler
from command import start, help_command, what_is_phishing, document_handler ,email_command, tips, start_analyze_url, analyze_url_received, analyze_question_gpt, ask_to_chat_gpt, tutorial, examples, decision_handler ,start_quiz, handle_quiz_answer, cancel, QUIZ_STATE ,WAITING_FOR_URL ,WAITING_FOR_MESSAGE

# Enable logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
# set higher logging level for httpx to avoid all GET and POST requests being logged
logging.getLogger("httpx").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


def main() -> None:
    """Start the bot."""
    # Creation of the application and bot's token.
    application = Application.builder().token(private.token).build()

    # on different commands - answer in Telegram
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("email", email_command))
    application.add_handler(CommandHandler('tips', tips))
    application.add_handler(CommandHandler("whatIsPhishing", what_is_phishing))
    application.add_handler(CommandHandler('tutorial', tutorial))
    application.add_handler(CommandHandler('examples', examples))
    quiz_handler = ConversationHandler(
        entry_points=[CommandHandler('quizPhishing', start_quiz)],
        states={QUIZ_STATE: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_quiz_answer)]},
        fallbacks=[],
    )
    url_handler = ConversationHandler(
        entry_points=[CommandHandler('analyzeUrl', start_analyze_url)],
        states={
            WAITING_FOR_URL: [MessageHandler(filters.TEXT & ~filters.COMMAND, analyze_url_received)],
        },
        fallbacks=[CommandHandler('cancel', cancel)],
    )
    analyze_message_handler = ConversationHandler(
    entry_points=[CommandHandler('askGPT', ask_to_chat_gpt)],
    states={
        WAITING_FOR_MESSAGE: [MessageHandler(filters.TEXT & ~filters.COMMAND, analyze_question_gpt)],
    },
    fallbacks=[CommandHandler('cancel', cancel)],
)


    application.add_handler(quiz_handler)
    application.add_handler(url_handler)
    application.add_handler(analyze_message_handler)
    application.add_handler(MessageHandler(filters.TEXT, decision_handler))
    
    # Document Handler
    application.add_handler(MessageHandler(filters.Document.ALL, document_handler))

    # Run the bot until the user presses Ctrl-C
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
