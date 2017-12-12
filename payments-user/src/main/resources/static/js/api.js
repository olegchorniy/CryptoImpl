(function () {

    window.API = {

        register: function () {
            return $.post('/ui/register');
        },

        startOutgoingSession: function (recipientId) {
            return $.post('/ui/outgoing/start', {
                recipientId: recipientId,
                chainLength: 10
            });
        },

        transferFunds: function (sessionId, amount) {
            return $.post('/ui/transfer', {
                sessionId: sessionId,
                amount: amount
            });
        },

        finishIncoming: function (sessionId) {
            return $.post('/ui/incoming/finish', {
                sessionId: sessionId
            });
        }
    };
})();