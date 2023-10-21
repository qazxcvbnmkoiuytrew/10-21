$("form[name=signup_form]").submit(function(e) {

    var $form = $(this);
    var $error = $form.find(".error");
    var data = $form.serialize();

    $.ajax({
        url: "/user/signup",
        type: "POST",
        data: data,
        dataType: "json",
        success: function(resp) {
            window.location.href = "/user/login";
            window.alert("註冊成功");
        },

        error: function(resp) {
        console.log(resp);
        if (resp && resp.responseJSON && resp.responseJSON.error) {
            $error.text(resp.responseJSON.error).removeClass("error--hidden");
        } else {
        // 处理没有返回JSON响应或没有error属性的情况
            $error.text("An error occurred").removeClass("error--hidden");
        }
}


    });
    e.preventDefault();

});

$("form[name=login_form]").submit(function(e) {

    var $form = $(this);
    var $error = $form.find(".error");
    var data = $form.serialize();

    $.ajax({
        url: "/user/login",
        type: "POST",
        data: data,
        dataType: "json",

        success: function(resp) {
            window.location.href = "/";
            window.alert("登入成功");
        },
        error: function(resp) {
        console.log(resp);
        if (resp.responseJSON && resp.responseJSON.error) {
            $error.text(resp.responseJSON.error).removeClass("error--hidden");
        } else {
            // 处理未定义的情况，或者提供一个默认值
            $error.text("An error occurred").removeClass("error--hidden");
        }
}


    });
    e.preventDefault();

});

$("form[name=update_user_form]").submit(function(e) {

    var $form = $(this);
    var $error = $form.find(".error");
    var data = $form.serialize();

    $.ajax({
        url: "/user/update_user",
        type: "POST",
        data: data,
        dataType: "json",
        success: function(resp) {
            window.location.href = "/dashboard/";
            window.alert("修改成功");
        },
        error: function(resp) {
            console.log(resp);
            $error.text(resp.responseJSON.error).removeClass("error--hidden")
            window.alert("修改失敗");
        }

    });
    e.preventDefault();

});

$('#password, #password_confirm').on('keyup', function(){

    $('.confirm-message').removeClass('success-message').removeClass('error-message');

    let password=$('#password').val();
    let confirm_password=$('#password_confirm').val();

    if(confirm_password===""){
        $('.confirm-message').text("Confirm Password Field cannot be empty").addClass('error-message');
    }
    else if(confirm_password===password)
    {
        $('.confirm-message').text('Password Match!').addClass('success-message');
    }
    else{
        $('.confirm-message').text("Password Doesn't Match!").addClass('error-message');
    }

    });

