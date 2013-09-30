<html>
<head>
<title>Ruby info page</title>

<script type="text/javascript">
function about() {
	if (Element.empty('about-content')) {
          new Ajax.Updater('about-content', 'rails/info/properties', {
            method:     'get',
            onFailure:  function()
{Element.classNames('about-content').add('failure')},
            onComplete: function() {new
Effect.BlindDown('about-content', {duration: 0.25})}
          });
        } else {
          new Effect[Element.visible('about-content') ?
            'BlindUp' : 'BlindDown']('about-content', {duration: 0.25});
        }
      }

      window.onload = function() {
        $('search-text').value = '';
        $('search').onsubmit = function() {
          $('search-text').value = 'site:rubyonrails.org ' +
$F('search-text');
        }
      }
    </script>
  </head>


<body>

 <div id="about">
          <h3><a href="rails/info/properties" onclick="about(); return
false">About your application&rsquo;s environment</a></h3>
          <div id="about-content" style="display: none"></div>
        </div>

</body>
</html>