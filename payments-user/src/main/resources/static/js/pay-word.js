$(function () {

    function refresh(param) {
        if (!param) {
            location.reload(true);
        } else {
            location.search = "?" + param.name + "=" + encodeURIComponent(param.value);
        }
    }

    $('#register-button').on('click', function () {
        API.register().done(refresh)
    });

    $('.js-vendor').on('click', function () {
        var vendorId = $(this).attr('data-vendor-id');
        refresh({name: 'recipient', value: vendorId})
    });

    $('#start-session-button').on('click', function () {
        var recipientId = $(this).attr('data-recipient-id');
        API.startOutgoingSession(recipientId).done(refresh);
    });

    $('#transfer-funds').on('click', function () {
        var sessionId = $(this).attr('data-session-id');
        var amount = $('#transfer-amount').val();

        API.transferFunds(sessionId, amount).done(refresh)
    });

    $('.js-finish-session').on('click', function () {
        var sessionId = $(this).attr('data-session-id');
        API.finishIncoming(sessionId).done(refresh)
    });
});