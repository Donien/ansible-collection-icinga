# netways.icinga.icingaweb2 role \-- Role to manage Icinga Web 2

This role is part of the [netways.icinga
collection](https://galaxy.ansible.com/ui/repo/published/netways/icinga/)
(version 0.4.2).

It is not included in `ansible-core`. To check whether it is installed,
run `ansible-galaxy collection list`.

To install it use: `ansible-galaxy collection install netways.icinga`.

To use it in a playbook, specify: `netways.icinga.icingaweb2`.

::: {.contents local="" depth="2"}
:::

## Entry point `main` \-- Role to manage Icinga Web 2 {#ansible_collections.netways.icinga.icingaweb2_role__entrypoint-main}

### Synopsis

-   Role to install, configure or manage Icinga Web 2 and official
    modules.

### Parameters

<table style="width: 100%;">
<thead>
  <tr>
  <th colspan="5"><p>Parameter</p></th>
  <th><p>Comments</p></th>
</tr>
</thead>
<tbody>
<tr>
  <td colspan="5" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_admin_password"></div>
    <p style="display: inline;"><strong>icingaweb2_admin_password</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_admin_password" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The password of the initial admin user for Icinga Web 2.</p>
  </td>
</tr>
<tr>
  <td colspan="5" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_admin_username"></div>
    <p style="display: inline;"><strong>icingaweb2_admin_username</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_admin_username" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The name of the initial admin user for Icinga Web 2.</p>
  </td>
</tr>
<tr>
  <td colspan="5" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_authentication"></div>
    <p style="display: inline;"><strong>icingaweb2_authentication</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_authentication" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>Specifies different authentication methods for Icinga Web 2.</p>
    <p>Each key in this dictionary represents an authentication method to be used. For a list of available options, see <a href='https://icinga.com/docs/icinga-web/latest/doc/05-Authentication/'>the official documentation</a>.</p>
    <p style="margin-top: 8px;"><b style="color: blue;">Default:</b> <code style="color: blue;">{&#34;icingaweb2&#34;: {&#34;backend&#34;: &#34;db&#34;, &#34;resource&#34;: &#34;icingaweb2_db&#34;}}</code></p>
  </td>
</tr>
<tr>
  <td colspan="5" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_config"></div>
    <p style="display: inline;"><strong>icingaweb2_config</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_config" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>This defines the general configuration of Icinga Web 2.</p>
    <p style="margin-top: 8px;"><b style="color: blue;">Default:</b> <code style="color: blue;">{&#34;global&#34;: {&#34;config_resource&#34;: &#34;icingaweb2_db&#34;, &#34;module_path&#34;: &#34;/usr/share/icingaweb2/modules&#34;, &#34;show_application_state_messages&#34;: 1, &#34;show_stacktraces&#34;: 1}, &#34;logging&#34;: {&#34;application&#34;: &#34;icingaweb2&#34;, &#34;facility&#34;: &#34;user&#34;, &#34;level&#34;: &#34;ERROR&#34;, &#34;log&#34;: &#34;syslog&#34;}, &#34;themes&#34;: {&#34;default&#34;: &#34;Icinga&#34;}}</code></p>
  </td>
</tr>
<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_config/global"></div>
    <p style="display: inline;"><strong>global</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_config/global" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>This defines global options for Icinga Web 2.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_config/global/config_resource"></div>
    <p style="display: inline;"><strong>config_resource</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_config/global/config_resource" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines which resource will be used by Icinga Web 2. Also see <code class="ansible-option literal notranslate"><strong><a class="reference internal" href="#parameter-main--icingaweb2_resources"><span class="std std-ref"><span class="pre">icingaweb2_resources</span></span></a></strong></code> and <code class="ansible-option literal notranslate"><strong><a class="reference internal" href="#parameter-main--icingaweb2_db"><span class="std std-ref"><span class="pre">icingaweb2_db</span></span></a></strong></code>.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_config/global/module_path"></div>
    <p style="display: inline;"><strong>module_path</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_config/global/module_path" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines where Icinga Web 2 modules are located on the filesystem.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_config/global/show_application_state_messages"></div>
    <p style="display: inline;"><strong>show_application_state_messages</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_config/global/show_application_state_messages" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">integer</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>Whether to show application state messages.</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code>0</code></p></li>
      <li><p><code>1</code></p></li>
    </ul>

  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_config/global/show_stacktraces"></div>
    <p style="display: inline;"><strong>show_stacktraces</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_config/global/show_stacktraces" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">integer</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>Whether to show stacktraces.</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code>0</code></p></li>
      <li><p><code>1</code></p></li>
    </ul>

  </td>
</tr>

<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_config/logging"></div>
    <p style="display: inline;"><strong>logging</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_config/logging" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the logging behavior of Icinga Web 2.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_config/logging/application"></div>
    <p style="display: inline;"><strong>application</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_config/logging/application" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>Specifies the application name if <code class="ansible-option-value literal notranslate"><a class="reference internal" href="#parameter-main--icingaweb2_config/logging/log"><span class="std std-ref"><span class="pre">icingaweb2_config.logging.log=syslog</span></span></a></code>.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_config/logging/facility"></div>
    <p style="display: inline;"><strong>facility</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_config/logging/facility" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>Specifies the syslog facility if <code class="ansible-option-value literal notranslate"><a class="reference internal" href="#parameter-main--icingaweb2_config/logging/log"><span class="std std-ref"><span class="pre">icingaweb2_config.logging.log=syslog</span></span></a></code>.</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code style="color: blue;"><b>&#34;user&#34;</b></code> <span style="color: blue;">← (default)</span></p></li>
      <li><p><code>&#34;local0&#34;</code></p></li>
      <li><p><code>&#34;local1&#34;</code></p></li>
      <li><p><code>&#34;local2&#34;</code></p></li>
      <li><p><code>&#34;local3&#34;</code></p></li>
      <li><p><code>&#34;local4&#34;</code></p></li>
      <li><p><code>&#34;local5&#34;</code></p></li>
      <li><p><code>&#34;local6&#34;</code></p></li>
      <li><p><code>&#34;local7&#34;</code></p></li>
    </ul>

  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_config/logging/file"></div>
    <p style="display: inline;"><strong>file</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_config/logging/file" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">path</span>
    </p>

  </td>
  <td valign="top">
    <p>Specifies the log file path if <code class="ansible-option-value literal notranslate"><a class="reference internal" href="#parameter-main--icingaweb2_config/logging/log"><span class="std std-ref"><span class="pre">icingaweb2_config.logging.log=file</span></span></a></code>.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_config/logging/level"></div>
    <p style="display: inline;"><strong>level</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_config/logging/level" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>Specifies the logging level.</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code>&#34;ERROR&#34;</code></p></li>
      <li><p><code>&#34;WARNING&#34;</code></p></li>
      <li><p><code>&#34;INFORMATION&#34;</code></p></li>
      <li><p><code>&#34;DEBUG&#34;</code></p></li>
    </ul>

  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_config/logging/log"></div>
    <p style="display: inline;"><strong>log</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_config/logging/log" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>Specifies the logging type.</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code>&#34;syslog&#34;</code></p></li>
      <li><p><code>&#34;file&#34;</code></p></li>
      <li><p><code>&#34;php&#34;</code></p></li>
      <li><p><code>&#34;none&#34;</code></p></li>
    </ul>

  </td>
</tr>

<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_config/themes"></div>
    <p style="display: inline;"><strong>themes</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_config/themes" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>Specifies the default theme for Icinga Web 2.</p>
  </td>
</tr>

<tr>
  <td colspan="5" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_db"></div>
    <p style="display: inline;"><strong>icingaweb2_db</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_db" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines Icinga Web&#x27;s own database resource for storing its configuration.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_db/host"></div>
    <p style="display: inline;"><strong>host</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_db/host" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The database host to be used.</p>
    <p style="margin-top: 8px;"><b style="color: blue;">Default:</b> <code style="color: blue;">&#34;localhost&#34;</code></p>
  </td>
</tr>
<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_db/name"></div>
    <p style="display: inline;"><strong>name</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_db/name" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>The name of the database to be used.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_db/password"></div>
    <p style="display: inline;"><strong>password</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_db/password" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>The database password to be used.</p>
    <p>If <code class="ansible-option literal notranslate"><strong><a class="reference internal" href="#parameter-main--icingaweb2_priv_db_password"><span class="std std-ref"><span class="pre">icingaweb2_priv_db_password</span></span></a></strong></code> is set, it will be used instead when interacting with the database. This is useful if the normal <code class="ansible-option literal notranslate"><strong><a class="reference internal" href="#parameter-main--icingaweb2_db/user"><span class="std std-ref"><span class="pre">icingaweb2_db.user</span></span></a></strong></code> cannot apply a database schema.</p>
    <p><code class="ansible-option literal notranslate"><strong><a class="reference internal" href="#parameter-main--icingaweb2_priv_db_password"><span class="std std-ref"><span class="pre">icingaweb2_priv_db_password</span></span></a></strong></code> works in conjunction with <code class="ansible-option literal notranslate"><strong><a class="reference internal" href="#parameter-main--icingaweb2_priv_db_user"><span class="std std-ref"><span class="pre">icingaweb2_priv_db_user</span></span></a></strong></code>.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_db/port"></div>
    <p style="display: inline;"><strong>port</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_db/port" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">integer</span>
    </p>

  </td>
  <td valign="top">
    <p>The database port to be used.</p>
    <p style="margin-top: 8px;"><b style="color: blue;">Default:</b> <code style="color: blue;">3306</code></p>
  </td>
</tr>
<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_db/ssl_ca"></div>
    <p style="display: inline;"><strong>ssl_ca</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_db/ssl_ca" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>If <code class="ansible-option-value literal notranslate"><a class="reference internal" href="#parameter-main--icingaweb2_db/type"><span class="std std-ref"><span class="pre">icingaweb2_db.type=mysql</span></span></a></code>, the for value for <code class='docutils literal notranslate'>--ssl-ca</code> to be passed to the <code class='docutils literal notranslate'>mysql</code> command when interacting with the database.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_db/ssl_cert"></div>
    <p style="display: inline;"><strong>ssl_cert</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_db/ssl_cert" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>If <code class="ansible-option-value literal notranslate"><a class="reference internal" href="#parameter-main--icingaweb2_db/type"><span class="std std-ref"><span class="pre">icingaweb2_db.type=mysql</span></span></a></code>, the for value for <code class='docutils literal notranslate'>--ssl-cert</code> to be passed to the <code class='docutils literal notranslate'>mysql</code> command when interacting with the database.</p>
    <p>If <code class="ansible-option-value literal notranslate"><a class="reference internal" href="#parameter-main--icingaweb2_db/type"><span class="std std-ref"><span class="pre">icingaweb2_db.type=pgsql</span></span></a></code>, the for value for <code class='docutils literal notranslate'>sslcert</code> to be passed to the <code class='docutils literal notranslate'>psql</code> command when interacting with the database.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_db/ssl_cipher"></div>
    <p style="display: inline;"><strong>ssl_cipher</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_db/ssl_cipher" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>If <code class="ansible-option-value literal notranslate"><a class="reference internal" href="#parameter-main--icingaweb2_db/type"><span class="std std-ref"><span class="pre">icingaweb2_db.type=mysql</span></span></a></code>, the for value for <code class='docutils literal notranslate'>--ssl-cipher</code> to be passed to the <code class='docutils literal notranslate'>mysql</code> command when interacting with the database.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_db/ssl_extra_options"></div>
    <p style="display: inline;"><strong>ssl_extra_options</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_db/ssl_extra_options" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>Any arbitrary extra options to be passed to the <code class='docutils literal notranslate'>mysql</code>/<code class='docutils literal notranslate'>psql</code> command when interacting with the database.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_db/ssl_key"></div>
    <p style="display: inline;"><strong>ssl_key</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_db/ssl_key" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>If <code class="ansible-option-value literal notranslate"><a class="reference internal" href="#parameter-main--icingaweb2_db/type"><span class="std std-ref"><span class="pre">icingaweb2_db.type=mysql</span></span></a></code>, the for value for <code class='docutils literal notranslate'>--ssl-key</code> to be passed to the <code class='docutils literal notranslate'>mysql</code> command when interacting with the database.</p>
    <p>If <code class="ansible-option-value literal notranslate"><a class="reference internal" href="#parameter-main--icingaweb2_db/type"><span class="std std-ref"><span class="pre">icingaweb2_db.type=pgsql</span></span></a></code>, the for value for <code class='docutils literal notranslate'>sslkey</code> to be passed to the <code class='docutils literal notranslate'>psql</code> command when interacting with the database.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_db/ssl_mode"></div>
    <p style="display: inline;"><strong>ssl_mode</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_db/ssl_mode" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>If <code class="ansible-option-value literal notranslate"><a class="reference internal" href="#parameter-main--icingaweb2_db/type"><span class="std std-ref"><span class="pre">icingaweb2_db.type=mysql</span></span></a></code>, the value for <code class='docutils literal notranslate'>--ssl-mode</code> to be passed to the <code class='docutils literal notranslate'>mysql</code> command when interacting with the database.</p>
    <p>If <code class="ansible-option-value literal notranslate"><a class="reference internal" href="#parameter-main--icingaweb2_db/type"><span class="std std-ref"><span class="pre">icingaweb2_db.type=pgsql</span></span></a></code>, the value for <code class='docutils literal notranslate'>ssl-mode</code> to be passed to the <code class='docutils literal notranslate'>psql</code> command when interacting with the database.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_db/type"></div>
    <p style="display: inline;"><strong>type</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_db/type" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The type of database to be used.</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code style="color: blue;"><b>&#34;mysql&#34;</b></code> <span style="color: blue;">← (default)</span></p></li>
      <li><p><code>&#34;pgsql&#34;</code></p></li>
    </ul>

  </td>
</tr>
<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_db/user"></div>
    <p style="display: inline;"><strong>user</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_db/user" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>The database user to be used.</p>
    <p>If <code class="ansible-option literal notranslate"><strong><a class="reference internal" href="#parameter-main--icingaweb2_priv_db_user"><span class="std std-ref"><span class="pre">icingaweb2_priv_db_user</span></span></a></strong></code> is set, it will be used instead when interacting with the database. This is useful if the normal <code class="ansible-option literal notranslate"><strong><a class="reference internal" href="#parameter-main--icingaweb2_db/user"><span class="std std-ref"><span class="pre">icingaweb2_db.user</span></span></a></strong></code> cannot apply a database schema.</p>
    <p><code class="ansible-option literal notranslate"><strong><a class="reference internal" href="#parameter-main--icingaweb2_priv_db_user"><span class="std std-ref"><span class="pre">icingaweb2_priv_db_user</span></span></a></strong></code> works in conjunction with <code class="ansible-option literal notranslate"><strong><a class="reference internal" href="#parameter-main--icingaweb2_priv_db_password"><span class="std std-ref"><span class="pre">icingaweb2_priv_db_password</span></span></a></strong></code>.</p>
  </td>
</tr>

<tr>
  <td colspan="5" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_db_import_schema"></div>
    <p style="display: inline;"><strong>icingaweb2_db_import_schema</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_db_import_schema" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">boolean</span>
    </p>

  </td>
  <td valign="top">
    <p>Whether the role should import the schema into the database initially.</p>
    <p>If <code class="ansible-option-value literal notranslate"><a class="reference internal" href="#parameter-main--icingaweb2_db_import_schema"><span class="std std-ref"><span class="pre">icingaweb2_db_import_schema=true</span></span></a></code>, information from <code class="ansible-option literal notranslate"><strong><a class="reference internal" href="#parameter-main--icingaweb2_db"><span class="std std-ref"><span class="pre">icingaweb2_db</span></span></a></strong></code> (and <code class="ansible-option literal notranslate"><strong><a class="reference internal" href="#parameter-main--icingaweb2_priv_db_user"><span class="std std-ref"><span class="pre">icingaweb2_priv_db_user</span></span></a></strong></code> / <code class="ansible-option literal notranslate"><strong><a class="reference internal" href="#parameter-main--icingaweb2_priv_db_password"><span class="std std-ref"><span class="pre">icingaweb2_priv_db_password</span></span></a></strong></code>) will be used to do so.</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code style="color: blue;"><b>false</b></code> <span style="color: blue;">← (default)</span></p></li>
      <li><p><code>true</code></p></li>
    </ul>

  </td>
</tr>
<tr>
  <td colspan="5" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_groups"></div>
    <p style="display: inline;"><strong>icingaweb2_groups</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_groups" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>Specifies different backends for assigning users to groups.</p>
    <p>Each key in this dictionary represents a group backend to be used. For a list of available options, see <a href='https://icinga.com/docs/icinga-web/latest/doc/05-Authentication/#groups'>the official documentation</a>.</p>
    <p style="margin-top: 8px;"><b style="color: blue;">Default:</b> <code style="color: blue;">{&#34;icingaweb2&#34;: {&#34;backend&#34;: &#34;db&#34;, &#34;resource&#34;: &#34;icingaweb2_db&#34;}}</code></p>
  </td>
</tr>
<tr>
  <td colspan="5" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules"></div>
    <p style="display: inline;"><strong>icingaweb2_modules</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>A dictionary of Icinga Web 2 modules.</p>
    <p>Each key is a specific module, each subkey is an option for the given module.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/director"></div>
    <p style="display: inline;"><strong>director</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/director" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>This configures the <a href='https://icinga.com/docs/icinga-db-web/latest/doc/03-Configuration/'>Icinga DB Web module</a>.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/director/config"></div>
    <p style="display: inline;"><strong>config</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/director/config" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the Director&#x27;s <code class='docutils literal notranslate'>config.ini</code> configuration file.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td colspan="2" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/director/config/db"></div>
    <p style="display: inline;"><strong>db</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/director/config/db" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the <code class='docutils literal notranslate'>db</code> section of the <code class='docutils literal notranslate'>config.ini</code> configuration file.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/director/config/db/resource"></div>
    <p style="display: inline;"><strong>resource</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/director/config/db/resource" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the database resource to be used.</p>
  </td>
</tr>


<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/director/enabled"></div>
    <p style="display: inline;"><strong>enabled</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/director/enabled" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">boolean</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>Whether the module should be enabled.</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code>false</code></p></li>
      <li><p><code>true</code></p></li>
    </ul>

  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/director/import_schema"></div>
    <p style="display: inline;"><strong>import_schema</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/director/import_schema" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">boolean</span>
    </p>

  </td>
  <td valign="top">
    <p>Whether the Director&#x27;s database schema should be initially imported initially.</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code>false</code></p></li>
      <li><p><code>true</code></p></li>
    </ul>

  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/director/kickstart"></div>
    <p style="display: inline;"><strong>kickstart</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/director/kickstart" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the Director&#x27;s <code class='docutils literal notranslate'>kickstart.ini</code> configuration file.</p>
    <p>This is required if <code class="ansible-option-value literal notranslate"><a class="reference internal" href="#parameter-main--icingaweb2_modules/director/run_kickstart"><span class="std std-ref"><span class="pre">icingaweb2_modules.director.run_kickstart=true</span></span></a></code>.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td colspan="2" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/director/kickstart/config"></div>
    <p style="display: inline;"><strong>config</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/director/kickstart/config" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the the <code class='docutils literal notranslate'>config</code> section in the <code class='docutils literal notranslate'>kickstart.ini</code> configuration file.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/director/kickstart/config/endpoint"></div>
    <p style="display: inline;"><strong>endpoint</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/director/kickstart/config/endpoint" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The Icinga 2 endpoint to deploy to.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/director/kickstart/config/host"></div>
    <p style="display: inline;"><strong>host</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/director/kickstart/config/host" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The initial host to run API commands against to get the actual endpoint object.</p>
    <p>Once a valid endpoint has been found, its attributes are used for actual deployments.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/director/kickstart/config/password"></div>
    <p style="display: inline;"><strong>password</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/director/kickstart/config/password" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The Icinga 2 API user&#x27;s password.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/director/kickstart/config/port"></div>
    <p style="display: inline;"><strong>port</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/director/kickstart/config/port" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The initial port to run API commands against to get the actual endpoint object.</p>
    <p>Once a valid endpoint has been found, its attributes are used for actual deployments.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/director/kickstart/config/username"></div>
    <p style="display: inline;"><strong>username</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/director/kickstart/config/username" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The Icinga 2 API user&#x27;s username.</p>
  </td>
</tr>


<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/director/run_kickstart"></div>
    <p style="display: inline;"><strong>run_kickstart</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/director/run_kickstart" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">boolean</span>
    </p>

  </td>
  <td valign="top">
    <p>Whether the Director&#x27;s kickstart should be run initially.</p>
    <p>Requires <code class="ansible-option literal notranslate"><strong><a class="reference internal" href="#parameter-main--icingaweb2_modules/director/kickstart"><span class="std std-ref"><span class="pre">icingaweb2_modules.director.kickstart</span></span></a></strong></code> to be defined.</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code>false</code></p></li>
      <li><p><code>true</code></p></li>
    </ul>

  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/director/source"></div>
    <p style="display: inline;"><strong>source</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/director/source" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the source from which to install the module</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code>&#34;package&#34;</code></p></li>
    </ul>

  </td>
</tr>

<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/graphite"></div>
    <p style="display: inline;"><strong>graphite</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/graphite" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>This configures the <a href='https://icinga.com/docs/icinga-web-graphite-integration/latest/doc/03-Configuration/'>Graphite module</a>.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/graphite/config"></div>
    <p style="display: inline;"><strong>config</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/graphite/config" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the Graphite module&#x27;s <code class='docutils literal notranslate'>config.ini</code> configuration file.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td colspan="2" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/graphite/config/graphite"></div>
    <p style="display: inline;"><strong>graphite</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/graphite/config/graphite" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the the <code class='docutils literal notranslate'>graphite</code> section in the <code class='docutils literal notranslate'>config.ini</code> configuration file.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/graphite/config/graphite/insecure"></div>
    <p style="display: inline;"><strong>insecure</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/graphite/config/graphite/insecure" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">integer</span>
    </p>

  </td>
  <td valign="top">
    <p>Disables TLS certificate verification.</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code>0</code></p></li>
      <li><p><code>1</code></p></li>
    </ul>

  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/graphite/config/graphite/password"></div>
    <p style="display: inline;"><strong>password</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/graphite/config/graphite/password" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The password to the Graphite Web instance.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/graphite/config/graphite/timeout"></div>
    <p style="display: inline;"><strong>timeout</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/graphite/config/graphite/timeout" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">integer</span>
    </p>

  </td>
  <td valign="top">
    <p>Timeout for HTTP requests to Graphite Web.</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code>0</code></p></li>
      <li><p><code>1</code></p></li>
    </ul>

  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/graphite/config/graphite/url"></div>
    <p style="display: inline;"><strong>url</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/graphite/config/graphite/url" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The URL to the Graphite Web instance.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/graphite/config/graphite/user"></div>
    <p style="display: inline;"><strong>user</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/graphite/config/graphite/user" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The username to the Graphite Web instance.</p>
  </td>
</tr>

<tr>
  <td></td>
  <td></td>
  <td></td>
  <td colspan="2" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/graphite/config/icinga"></div>
    <p style="display: inline;"><strong>icinga</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/graphite/config/icinga" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the the <code class='docutils literal notranslate'>icinga</code> section in the <code class='docutils literal notranslate'>config.ini</code> configuration file.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/graphite/config/icinga/customvar_obscured_check_command"></div>
    <p style="display: inline;"><strong>customvar_obscured_check_command</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/graphite/config/icinga/customvar_obscured_check_command" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The Icinga custom variable with the "actual" check command obscured by e.g. check_by_ssh.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/graphite/config/icinga/graphite_writer_host_name_template"></div>
    <p style="display: inline;"><strong>graphite_writer_host_name_template</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/graphite/config/icinga/graphite_writer_host_name_template" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The name of the Icinga 2 GraphiteWriter&#x27;s attribute <code class='docutils literal notranslate'>host_name_template</code>.</p>
    <p>This is only needed if the writer does not use the default.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/graphite/config/icinga/graphite_writer_service_name_template"></div>
    <p style="display: inline;"><strong>graphite_writer_service_name_template</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/graphite/config/icinga/graphite_writer_service_name_template" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The name of the Icinga 2 GraphiteWriter&#x27;s attribute <code class='docutils literal notranslate'>service_name_template</code>.</p>
    <p>This is only needed if the writer does not use the default.</p>
  </td>
</tr>

<tr>
  <td></td>
  <td></td>
  <td></td>
  <td colspan="2" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/graphite/config/ui"></div>
    <p style="display: inline;"><strong>ui</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/graphite/config/ui" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the the <code class='docutils literal notranslate'>ui</code> section in the <code class='docutils literal notranslate'>config.ini</code> configuration file.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/graphite/config/ui/default_time_range"></div>
    <p style="display: inline;"><strong>default_time_range</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/graphite/config/ui/default_time_range" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The default time range to be displayed.</p>
    <p>The value of <code class="ansible-option literal notranslate"><strong><a class="reference internal" href="#parameter-main--icingaweb2_modules/graphite/config/ui/default_time_range_unit"><span class="std std-ref"><span class="pre">icingaweb2_modules.graphite.config.ui.default_time_range_unit</span></span></a></strong></code> is used as the unit to this value.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/graphite/config/ui/default_time_range_unit"></div>
    <p style="display: inline;"><strong>default_time_range_unit</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/graphite/config/ui/default_time_range_unit" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The default time range unit to be used.</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code>&#34;minutes&#34;</code></p></li>
      <li><p><code>&#34;hours&#34;</code></p></li>
      <li><p><code>&#34;days&#34;</code></p></li>
      <li><p><code>&#34;weeks&#34;</code></p></li>
      <li><p><code>&#34;months&#34;</code></p></li>
      <li><p><code>&#34;years&#34;</code></p></li>
    </ul>

  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/graphite/config/ui/disable_no_graphs_found"></div>
    <p style="display: inline;"><strong>disable_no_graphs_found</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/graphite/config/ui/disable_no_graphs_found" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">integer</span>
    </p>

  </td>
  <td valign="top">
    <p>Disables graphs completely for monitored objects without graphs. Shows nothing at all.</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code>0</code></p></li>
      <li><p><code>1</code></p></li>
    </ul>

  </td>
</tr>


<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/graphite/enabled"></div>
    <p style="display: inline;"><strong>enabled</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/graphite/enabled" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">boolean</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>Whether the module should be enabled.</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code>false</code></p></li>
      <li><p><code>true</code></p></li>
    </ul>

  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/graphite/source"></div>
    <p style="display: inline;"><strong>source</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/graphite/source" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the source from which to install the module</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code>&#34;package&#34;</code></p></li>
    </ul>

  </td>
</tr>

<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb"></div>
    <p style="display: inline;"><strong>icingadb</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>This configures the <a href='https://icinga.com/docs/icinga-db-web/latest/doc/03-Configuration/'>Icinga DB Web module</a>.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/commandtransports"></div>
    <p style="display: inline;"><strong>commandtransports</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/commandtransports" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the command transports to be used.</p>
    <p>Each key defines a command transport. Each subkey defines an option to that command transport.</p>
    <p>Example: <code class='docutils literal notranslate'>instance01: { transport: api, host: 10.0.0.10, port: 5665, username: root, password: changeme }, instance02: { transport: api, host: 10.0.0.20, port: 5665, username: root, password: changeme }</code></p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/config"></div>
    <p style="display: inline;"><strong>config</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/config" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the general module settings.</p>
    <p>Each key defines a section of the INI configuration. Each subkey defines an option to that section.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td colspan="2" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/config/icingadb"></div>
    <p style="display: inline;"><strong>icingadb</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/config/icingadb" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the <code class='docutils literal notranslate'>icingadb</code> section of the configuration file.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/config/icingadb/resource"></div>
    <p style="display: inline;"><strong>resource</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/config/icingadb/resource" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>Sets the module&#x27;s database resource.</p>
  </td>
</tr>

<tr>
  <td></td>
  <td></td>
  <td></td>
  <td colspan="2" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/config/redis"></div>
    <p style="display: inline;"><strong>redis</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/config/redis" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the <code class='docutils literal notranslate'>redis</code> section of the configuration file.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/config/redis/ca"></div>
    <p style="display: inline;"><strong>ca</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/config/redis/ca" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">path</span>
    </p>

  </td>
  <td valign="top">
    <p>The path to the CA certificate in PEM format.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/config/redis/cert"></div>
    <p style="display: inline;"><strong>cert</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/config/redis/cert" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">path</span>
    </p>

  </td>
  <td valign="top">
    <p>The path to the client certificate in PEM format.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/config/redis/key"></div>
    <p style="display: inline;"><strong>key</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/config/redis/key" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">path</span>
    </p>

  </td>
  <td valign="top">
    <p>The path to the client key in PEM format.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/config/redis/tls"></div>
    <p style="display: inline;"><strong>tls</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/config/redis/tls" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">integer</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines whether TLS encryption should be used.</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code>0</code></p></li>
      <li><p><code>1</code></p></li>
    </ul>

  </td>
</tr>


<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/enabled"></div>
    <p style="display: inline;"><strong>enabled</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/enabled" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">boolean</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>Whether the module should be enabled.</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code>false</code></p></li>
      <li><p><code>true</code></p></li>
    </ul>

  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/redis"></div>
    <p style="display: inline;"><strong>redis</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/redis" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the redis configuration.</p>
    <p>Each key defines the connection to a redis instance. Each subkey defines an option to that connection.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td colspan="2" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/redis/redis1"></div>
    <p style="display: inline;"><strong>redis1</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/redis/redis1" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the connection to the first redis instance.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/redis/redis1/database"></div>
    <p style="display: inline;"><strong>database</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/redis/redis1/database" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">integer</span>
    </p>

  </td>
  <td valign="top">
    <p>The database identifier.</p>
    <p>This is only needed if Icinga 2 is configured to write into another database index.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/redis/redis1/host"></div>
    <p style="display: inline;"><strong>host</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/redis/redis1/host" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The address of the redis instance.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/redis/redis1/password"></div>
    <p style="display: inline;"><strong>password</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/redis/redis1/password" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The password for the redis instance.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/redis/redis1/port"></div>
    <p style="display: inline;"><strong>port</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/redis/redis1/port" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">integer</span>
    </p>

  </td>
  <td valign="top">
    <p>The port of the redis instance.</p>
    <p>Icinga DB Redis uses <code class='docutils literal notranslate'>6380</code> by default.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/redis/redis1/username"></div>
    <p style="display: inline;"><strong>username</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/redis/redis1/username" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The username for the redis instance.</p>
  </td>
</tr>

<tr>
  <td></td>
  <td></td>
  <td></td>
  <td colspan="2" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/redis/redis2"></div>
    <p style="display: inline;"><strong>redis2</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/redis/redis2" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the connection to the second redis instance.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/redis/redis2/database"></div>
    <p style="display: inline;"><strong>database</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/redis/redis2/database" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">integer</span>
    </p>

  </td>
  <td valign="top">
    <p>The database identifier.</p>
    <p>This is only needed if Icinga 2 is configured to write into another database index.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/redis/redis2/host"></div>
    <p style="display: inline;"><strong>host</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/redis/redis2/host" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The address of the redis instance.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/redis/redis2/password"></div>
    <p style="display: inline;"><strong>password</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/redis/redis2/password" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The password for the redis instance.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/redis/redis2/port"></div>
    <p style="display: inline;"><strong>port</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/redis/redis2/port" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">integer</span>
    </p>

  </td>
  <td valign="top">
    <p>The port of the redis instance.</p>
    <p>Icinga DB Redis uses <code class='docutils literal notranslate'>6380</code> by default.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td></td>
  <td></td>
  <td></td>
  <td valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/redis/redis2/username"></div>
    <p style="display: inline;"><strong>username</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/redis/redis2/username" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>The username for the redis instance.</p>
  </td>
</tr>


<tr>
  <td></td>
  <td></td>
  <td colspan="3" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_modules/icingadb/source"></div>
    <p style="display: inline;"><strong>source</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_modules/icingadb/source" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines the source from which to install the module</p>
    <p style="margin-top: 8px;"><b">Choices:</b></p>
    <ul>
      <li><p><code>&#34;package&#34;</code></p></li>
    </ul>

  </td>
</tr>


<tr>
  <td colspan="5" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_resources"></div>
    <p style="display: inline;"><strong>icingaweb2_resources</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_resources" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>Defines Icinga Web 2 resources. A resource can be a database connection, LDAP connection, or SSH.</p>
    <p>Each key in the dictionary represents a resource. Each resource type supports different options. See <a href='https://icinga.com/docs/icinga-web/latest/doc/04-Resources/#database'>database resource</a>, <a href='https://icinga.com/docs/icinga-web/latest/doc/04-Resources/#ldap'>LDAP resource</a>, and <a href='https://icinga.com/docs/icinga-web/latest/doc/04-Resources/#ssh'>SSH resource</a> for valid options.</p>
    <p>Example: <code class='docutils literal notranslate'>icingaweb2_resources: { icingadb_db: { type: db, db: mysql, host: localhost, dbname: icingadb, username: icingadb_user, password: icingadb_password, use_ssl: 0 charset: utf8 } }</code></p>
  </td>
</tr>
<tr>
  <td colspan="5" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_roles"></div>
    <p style="display: inline;"><strong>icingaweb2_roles</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_roles" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>A dictionary of roles for Icinga Web 2.</p>
    <p>Each key is a role, each subkey is an option for the given role. See <a href='https://icinga.com/docs/icinga-web/latest/doc/06-Security/#configuration'>Icinga Web Roles</a> for valid options.</p>
    <p>Modules can also extend the permission system, so it is not possible to document all options here.</p>
    <p>Example: <code class='docutils literal notranslate'>icingaweb2_roles: { watchers: { users: [ user1, user2 ], permissions: [ module/icingadb, icingadb/command/downtime/* ], icingadb/filter/hosts: host.name=*windows* } }</code></p>
  </td>
</tr>
<tr>
  <td colspan="5" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_users"></div>
    <p style="display: inline;"><strong>icingaweb2_users</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_users" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">list</span>
      / <span style="color: purple;">elements=dictionary</span>
    </p>

  </td>
  <td valign="top">
    <p>A list of additional Icinga Web 2 users to create.</p>
    <p>Requires <code class="ansible-option literal notranslate"><strong><a class="reference internal" href="#parameter-main--icingaweb2_db"><span class="std std-ref"><span class="pre">icingaweb2_db</span></span></a></strong></code> to be defined.</p>
    <p style="margin-top: 8px;"><b style="color: blue;">Default:</b> <code style="color: blue;">[]</code></p>
  </td>
</tr>
<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_users/password"></div>
    <p style="display: inline;"><strong>password</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_users/password" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>The password of the user to create.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_users/recreate"></div>
    <p style="display: inline;"><strong>recreate</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_users/recreate" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
    </p>

  </td>
  <td valign="top">
    <p>Whether to update the password for the given user.</p>
  </td>
</tr>
<tr>
  <td></td>
  <td colspan="4" valign="top">
    <div class="ansibleOptionAnchor" id="parameter-main--icingaweb2_users/username"></div>
    <p style="display: inline;"><strong>username</strong></p>
    <a class="ansibleOptionLink" href="#parameter-main--icingaweb2_users/username" title="Permalink to this option"></a>
    <p style="font-size: small; margin-bottom: 0;">
      <span style="color: purple;">string</span>
      / <span style="color: red;">required</span>
    </p>

  </td>
  <td valign="top">
    <p>The name of the user to create.</p>
  </td>
</tr>

</tbody>
</table>

### Authors

-   Lennart Betz
-   Thilo Wening
-   Thomas Widhalm

#### Collection links

-   [Issue
    Tracker](https://github.com/NETWAYS/ansible-collection-icinga/issues)
-   [Repository
    (Sources)](https://github.com/NETWAYS/ansible-collection-icinga)
