(function () {

    function render(template, params) {
        return $.ajax({
            url: '/render',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({
                template: template,
                params: params
            })
        });
    }

    window.Renderer = {
        render: function (template, params) {
            return render(template, params);
        },

        renderTo: function (container, template, params) {
            return render(template, params)
                .then(function (response) {
                    var $container = $(container);
                    $container.html(response);

                    return $container;
                })
                .fail(function (jqXHR) {
                    alert("Render failed: " + jqXHR.response)
                });
        }
    };
})();