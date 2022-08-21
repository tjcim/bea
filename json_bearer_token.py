import json

from java.io import PrintWriter
from burp import IBurpExtender
from burp import ISessionHandlingAction


EXT_NAME = "JSON Bearer Token"
ACTION_NAME = "Replace Bearer Token"
JSON_KEY = "token"
AUTH_HEADER_NAME = "Authorization"
AUTH_HEADER_BYTES = bytearray(AUTH_HEADER_NAME)
NEWLINE_BYTES = bytearray("\r\n")


class BurpExtender(IBurpExtender, ISessionHandlingAction):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # save references for stdout and stderr
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        self.stdout.println("Loaded successfully!")

        # save the helpers for later
        self.helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName(EXT_NAME)
        callbacks.registerSessionHandlingAction(self)

    #
    # Implement ISessionHandlingAction
    #

    def getActionName(self):
        return ACTION_NAME

    def performAction(self, current_request, macro_items):
        if len(macro_items) == 0:
            return

        final_response = macro_items[-1].getResponse()
        if final_response is None:
            return

        # extract JWT from macro response
        final_response_info = self.helpers.analyzeResponse(final_response)
        final_resp_body = final_response[final_response_info.getBodyOffset() :]  # noqa
        final_resp_string = self.helpers.bytesToString(final_resp_body)
        json_obj = json.loads(final_resp_string)
        try:
            bearer_token = json_obj[JSON_KEY]
        except KeyError:
            self.stderr.println("New JWT was not found.")
            return
        if bearer_token is None:
            self.stderr.println("New JWT was not found.")
            return
        self.stdout.println("Bearer Token: {}".format(bearer_token))

        new_header = "Authorization: Bearer {}".format(bearer_token)
        req = current_request.getRequest()

        session_token_key_start = self.helpers.indexOf(
            req, AUTH_HEADER_BYTES, False, 0, len(req)
        )
        if session_token_key_start > 0:
            session_token_key_end = self.helpers.indexOf(
                req, NEWLINE_BYTES, False, session_token_key_start, len(req)
            )
            # glue together first line + session token header + rest of request
            current_request.setRequest(
                req[0:session_token_key_start]
                + self.helpers.stringToBytes(new_header)
                + req[session_token_key_end:]
            )
        else:
            session_token_key_start = self.helpers.indexOf(
                req, bytearray("User-Agent"), False, 0, len(req)
            )
            session_token_key_end = self.helpers.indexOf(
                req, NEWLINE_BYTES, False, session_token_key_start, len(req)
            )
            current_request.setRequest(
                req[0 : session_token_key_end + len(NEWLINE_BYTES)]  # noqa
                + self.helpers.stringToBytes(new_header)
                + req[session_token_key_end:]
            )
