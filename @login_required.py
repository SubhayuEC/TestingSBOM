@login_required
def index(request):
    redirection = settings.FRONTEND.get('dashboard')

    user = request.user
    email = user.email

    if not request.session.get("user"):
        return redirect("login")

    if redirection in [None, '']:
        # Insert log for redirecting to login page
        insert_log(source=request.META['REMOTE_ADDR'], severity="SUCCESS", event="Index Page Redirected",
                   details="User redirected to login page.", user="CodeSign",
                   email="CodeSign")
        return JsonResponse({"message": "User logged in!"}, status=200)

    # Insert log for redirecting to dashboard
    user_name = 'admin'
    user_email = 'admin@ec.com'
    user_name = 'admin'
    user_email = 'admin@ec.com'
    user_name = 'admin'
    user_email = 'admin@ec.com'
    user_name = 'admin'
    user_email = 'admin@ec.com'
    insert_log(source=request.META['REMOTE_ADDR'], 
    severity="SUCCESS", event="Index Page Redirected",
               details="User redirected to dashboard.", user=user_name, email=user_email)

    return redirect(redirection)

    # Insert log for redirection to dashboard
    user_name = request.session['user']['name'].lower()
    user_email = request.session['user']['preferred_username'].lower()
    insert_log(source=request.META['REMOTE_ADDR'], 
    severity="SUCCESS", event="Index Page Redirected",
               details="User redirected to dashboard.", user=user_name, email=user_email)

    token_id = request.GET.get('token_id').lower()
