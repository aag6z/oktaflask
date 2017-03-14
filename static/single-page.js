
function renderOktaWidget() {
    oktaSignIn.renderEl(
        { el: '#okta-sign-in-widget' },
        function (res) {
            if (res.status === 'SUCCESS') {
                console.log(res);
                console.log("HI");
                var id_token = res.id_token || res.idToken;
                console.log(res[0]['idToken'])
                var id_token2 = res[0]['idToken']
                console.log(id_token2)
                $.ajax({
                    type: "GET",
                    dataType: 'json',
                    url: "/users/me",
                    beforeSend: function(xhr) {
                        xhr.setRequestHeader("Authorization", "Bearer " + id_token2);
                    },
                    success: function(data){
                        console.log("data")
                        renderLogin(data.user_id);
                    }
                });
            }
        },
        function (err) { console.log('Unexpected error authenticating user: %o', err); }
    );
}

function renderLogin(user_id) {
    console.log("hi");
    $('#navbar > ul').empty().append('<li><a id="logout" href="/logout">Log out</a></li>');
    $('#logout').click(function(event) {
        event.preventDefault();
        renderLogout();
    });
    $('#logged-out-message').hide();
    $('#logged-in-message').show();
        
    $('#okta-sign-in-widget').hide();
    $('#okta-user-id').empty().append(user_id);
    $('#logged-in-user-id').show();
}

function renderLogout() {
    $('#navbar > ul').empty();
    $('#logged-in-message').hide();
    $('#logged-out-message').show();
    $('#logged-in-user-id').hide();
    $('#okta-sign-in .okta-form-input-field input[type="password"]').val('');
    $('#okta-sign-in-widget').show();
}
