$(function () {

    function refresh() {
        location.reload(true);
    }

    $('#register-button').on('click', function () {
        API.register().done(refresh)
    });
});