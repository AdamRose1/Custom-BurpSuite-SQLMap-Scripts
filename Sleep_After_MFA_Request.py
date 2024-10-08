from burp import IBurpExtender, IExtensionStateListener, IHttpListener, IHttpRequestResponse, ISessionHandlingAction
import time

class BurpExtender(IBurpExtender, IExtensionStateListener, IHttpListener, ISessionHandlingAction):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Request Delay Extension")
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerSessionHandlingAction(self)
        
        # Add action to session handling rules
        self._callbacks.addSessionHandlingAction(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            request = messageInfo.getRequest()
            # Get the request body
            body = self._helpers.bytesToString(request).split("\r\n\r\n", 1)[1]
            # Check if 'SMS_MFA_CODE' is in the body
            if 'SMS_MFA_CODE' in body:
                # Introduce delay
                time.sleep(30)

    def getActionName(self):
        return "Introduce Delay After Request"

    def performAction(self, currentRequestResponse):
        # This will be called when the action is selected
        self._callbacks.printOutput("Delay action invoked!")
        time.sleep(30)
