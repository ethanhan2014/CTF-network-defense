import os
import slack_sdk

from dotenv import load_dotenv


load_dotenv()
TOKEN = os.environ['SLACK_TOKEN']
CHANNEL = os.environ['SLACK_CHANNEL']


class Bot:
    client = slack_sdk.WebClient(token=TOKEN)

    @classmethod
    def alert_channel(cls, message):
        """ Helper that sends a message to slack channel

        :param message: (str) string to send in alert

        Example:
            bot = message_bot.Bot()
            bot.alert_channel("Hello World")

        """
        cls.client.chat_postMessage(channel=CHANNEL, text=message)
