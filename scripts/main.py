#!/usr/bin/env python3

from argparse import ArgumentParser
from configparser import ConfigParser, Error as ConfigParserError
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from logging import basicConfig, DEBUG, INFO, getLogger
from os import getcwd
from os.path import join
import re
import requests
from typing import List

from pytools.email import SMTPSender, IMAPReceiver


logger = getLogger(__name__)


thumbnail_pattern = re.compile("<img.*src=(.*?)\"(.*?)\" />", re.MULTILINE | re.DOTALL)


def parse_args():
    parser = ArgumentParser(description='ArloEmail2PicMessage - Converts Arlo Email to picture message')
    parser.add_argument('settings', help='Settings file', nargs='?', default=join(getcwd(), "settings.ini"))
    parser.add_argument('-c', '--create', help='Create settings file', default=False, action='store_true')
    parser.add_argument('-v', '--verbose', help='Verbose logs', default=False, action='store_true')

    return parser.parse_args()


def create_ini(filename):
    config = ConfigParser()

    config.add_section("app")
    config.set("app", "alert_from_address", "")
    config.set("app", "alert_recipient_addresses", "")

    config.add_section("email")
    config.set("email", "smtp_username", "")
    config.set("email", "smtp_password", "")
    config.set("email", "smtp_server", "")
    config.set("email", "smtp_port", "")
    config.set("email", "imap_username", "")
    config.set("email", "imap_password", "")
    config.set("email", "imap_server", "")

    with open(filename, "w") as f:
        config.write(f)

def read_config_file(filename):
    logger.debug("Reading config file, %s", filename)

    config = ConfigParser()
    config.read(filename)

    logger.debug("Read config file")

    return config


class FailedToCreateSMTPSender(RuntimeError):
    pass


def create_SMTPSender(config):

    try:
        username = config.get("email", "smtp_username")
        password = config.get("email", "smtp_password")
        server = config.get("email", "smtp_server")
        port = config.getint("email", "smtp_port")

    except ConfigParserError as e:
        logger.exception("Failed to read smtp settings from config file. %s", e.message)
        raise FailedToCreateSMTPSender()

    return SMTPSender(username, password, server, port)


class FailedToCreateIMAPReciever(RuntimeError):
    pass


def create_IMAPReceiver(config):

    try:
        username = config.get("email", "imap_username")
        password = config.get("email", "imap_password")
        server = config.get("email", "imap_server")

    except ConfigParserError as e:
        logger.exception("Failed to read imap settings from config file. %s", e.message)
        raise FailedToCreateIMAPReciever()

    return IMAPReceiver(username, password, server)


def process_message(message: MIMEBase, smtp: SMTPSender, fwd_originator: str, fwd_recipients: List[str]):
    source = ""

    logger.debug("Processing message")
    if message.is_multipart():
        logger.debug("Message is multipart... making a guess at payload.")
        for payload in message.walk():
            source = payload.as_string()
            break

    else:
        source = message.get_payload().as_string()

    match = thumbnail_pattern.search(source)

    prefix = match.group(1)
    url = match.group(2)

    url = url.replace("=\n", "")
    url = url.replace("=" + prefix, "=")

    logger.debug("Getting thumbnail: %s", url)
    thumbnail = requests.get(url)

    msg = make_forward(originator=fwd_originator, recipients=fwd_recipients, thumbnail=thumbnail)

    smtp.send(msg)

    logger.debug("Completed processing message")


def make_forward(originator, recipients, thumbnail, subject=None):
    msg = MIMEMultipart()
    msg['From'] = originator
    msg['To'] = ", ".join(recipients)

    if subject:
        msg['Subject'] = subject

    msg.preamble = 'image'
    img = MIMEImage(thumbnail.content, 'jpg')
    msg.add_header('Content-Disposition', 'attachment', filename='image.jpg')
    msg.attach(img)
    return msg


def run(args):
    config = read_config_file(args.settings)
    smtp = create_SMTPSender(config)
    imap = create_IMAPReceiver(config)
    logger.info("SMTP and IMAP interfaces created: %s", smtp)

    alerts_from = config.get("app", "alert_from_address")
    emails = imap.get_emails("alerts@arlo.com")

    logger.info("Processing %d new messages", len(emails))

    alert_recipients = config.get("app", "alert_recipient_addresses").split(", ")
    fwd_originator = config.get("email", "smtp_username")

    for i, email in enumerate(emails):
        try:
            process_message(message=email,
                            smtp=smtp,
                            fwd_originator=fwd_originator,
                            fwd_recipients=alert_recipients)
        except Exception as e:
            logger.exception("Failed to process message: %d", i)

    logger.info("Done")


def main():
    logging_config = dict(level=INFO,
                          format='[%(asctime)s - %(filename)s:%(lineno)d - %(funcName)s - %(levelname)s] %(message)s')
    basicConfig(**logging_config)

    args = parse_args()

    if args.verbose:
        getLogger('').setLevel(DEBUG)

    if not args.create:
        run(args)
    else:
        create_ini(args.settings)


if __name__ == "__main__":
    main()
