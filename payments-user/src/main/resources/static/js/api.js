(function () {

    window.API = {

        register: function () {
            return $.post('/ui/register');
        }
    };
})();