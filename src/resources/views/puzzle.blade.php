<html>
  <head>
    <title>Human Verification - Alexis</title>
    <script type="text/javascript">
      var onloadCallback = function() {
        grecaptcha.render('html_element', {
          sitekey: "{{ config('services.recaptcha.site_key') }}"
        });
      };
    </script>
  </head>
  <body>
    <form action="{{ url('alexis-verify') }}" method="POST">
      @csrf
      <div id="html_element"></div>
      <br>
      <input type="submit" value="Submit">
    </form>

    <script src="https://www.google.com/recaptcha/api.js?onload=onloadCallback&render=explicit"
      async defer></script>
  </body>
</html>
