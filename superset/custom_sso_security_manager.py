# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# pylint: disable=C,R,W
"""A set of constants and methods to manage permissions and security"""
import logging

from flask import (g,redirect,request,flash,url_for,session)
from flask_appbuilder import AppBuilder, IndexView, SQLA
from flask_appbuilder.security.views import (AuthView, expose)
from flask_appbuilder._compat import as_unicode
from flask_login import login_user, logout_user
import jwt

from superset.security import SupersetSecurityManager
# import superset.models.core as models

log = logging.getLogger(__name__)


class CustomAuthOAuthView(AuthView):
    login_template = "appbuilder/general/security/login_oauth.html"

    @expose("/login/")
    @expose("/login/<provider>")
    @expose("/login/<provider>/<register>")
    def login(self, provider=None, register=None):
        log.debug("Provider: {0}".format(provider))
        if g.user is not None and g.user.is_authenticated:
            log.debug("Already authenticated {0}".format(g.user))
            return redirect(self.appbuilder.get_url_for_index)
        if provider is None:
            return self.render_template(
                self.login_template,
                providers=self.appbuilder.sm.oauth_providers,
                title=self.title,
                appbuilder=self.appbuilder,
            )
        else:
            log.debug("Going to call authorize for: {0}".format(provider))
            state = jwt.encode(
                request.args.to_dict(flat=False),
                self.appbuilder.app.config["SECRET_KEY"],
                algorithm="HS256",
            )
            try:
                if register:
                    log.debug("Login to Register")
                    session["register"] = True
                if provider == "twitter":
                    return self.appbuilder.sm.oauth_remotes[provider].authorize(
                        callback=url_for(
                            ".oauth_authorized",
                            provider=provider,
                            _external=True,
                            state=state,
                        )
                    )
                else:
                    #get need mutil_tenant
                    mutil_tenant = self.appbuilder.app.config["MULTI_TENANT"]
                    if mutil_tenant:
                        #get tenantcode
                        teanant_code = request.args.get('amp;tenantcode')
                        if teanant_code is not None:
                            provider = teanant_code

                    return self.appbuilder.sm.oauth_remotes[provider].authorize(
                        callback=url_for(
                            ".oauth_authorized", provider=provider, _external=True
                        ),
                        state=state,
                    )
            except Exception as e:
                log.error("Error on OAuth authorize: {0}".format(e))
                flash(as_unicode(self.invalid_login_message), "warning")
                return redirect(self.appbuilder.get_url_for_index)

    @expose("/oauth-authorized/<provider>")
    def oauth_authorized(self, provider):
        log.debug("Authorized init")
        resp = self.appbuilder.sm.oauth_remotes[provider].authorized_response()
        if resp is None:
            flash(u"You denied the request to sign in.", "warning")
            return redirect("login")
        log.debug("OAUTH Authorized resp: {0}".format(resp))
        # Retrieves specific user info from the provider
        try:
            self.appbuilder.sm.set_oauth_session(provider, resp)
            userinfo = self.appbuilder.sm.oauth_user_info(provider, resp)
        except Exception as e:
            log.error("Error returning OAuth user info: {0}".format(e))
            user = None
        else:
            log.debug("User info retrieved from {0}: {1}".format(provider, userinfo))
            # User email is not whitelisted
            if provider in self.appbuilder.sm.oauth_whitelists:
                whitelist = self.appbuilder.sm.oauth_whitelists[provider]
                allow = False
                for e in whitelist:
                    if re.search(e, userinfo["email"]):
                        allow = True
                        break
                if not allow:
                    flash(u"You are not authorized.", "warning")
                    return redirect("login")
            else:
                log.debug("No whitelist for OAuth provider")
            user = self.appbuilder.sm.auth_user_oauth(userinfo)

        if user is None:
            flash(as_unicode(self.invalid_login_message), "warning")
            return redirect("login")
        else:
            login_user(user)
            try:
                state = jwt.decode(
                    request.args["state"],
                    self.appbuilder.app.config["SECRET_KEY"],
                    algorithms=["HS256"],
                )
            except jwt.InvalidTokenError:
                raise Exception("State signature is not valid!")

            try:
                next_url = state["next"][0] or self.appbuilder.get_url_for_index
            except (KeyError, IndexError):
                next_url = self.appbuilder.get_url_for_index

            #commit  user_attributes
            from superset import app, db
            from superset.models.user_attributes import UserAttribute
            session = db.session()
            #find is exist
            user_attribute = session.query(UserAttribute).filter_by(user_id = user.id).one_or_none()
            if user_attribute is None:
                user_attribute = UserAttribute(user_id = user.id,tenant_code = provider)
                try:
                    session.add(user_attribute)
                    session.commit()
                except Exception as e:
                    session.rollback()
                    raise Exception("Error Save UserAttribute {0} ".format(e))
            else:
                user_attribute.tenant_code = provider
                try:
                    session.commit()
                except Exception as e:
                    session.rollback()
                    raise Exception("Error Save UserAttribute {0} ".format(e))


            return redirect(next_url)


class CustomSsoSecurityManager(SupersetSecurityManager):
    authoauthview = CustomAuthOAuthView

    def oauth_user_info(self, provider, response=None):
        # return {'email':'userisxkk@hotmail.com'}
        if provider == "github" or provider == "githublocal":
            me = self.appbuilder.sm.oauth_remotes[provider].get("user")
            logging.debug(">>>>>>>>>>>>>>>>>>>>>>>>User info from Github: {0}<<<<<<<<<<<<<<<<<<<<<<<<".format(me.data))
            loginName = me.data.get("login")
            return {"username": "github_" + loginName,
            "email":"%s@rektec.com" % loginName}
        elif provider == "superset" or provider == "crm_dev1" or provider == "crm_dev1030":
            me = self.appbuilder.sm.oauth_remotes[provider].get("userinfo")
            loginName = me.data.get('preferred_username')
            email = me.data.get('email')
            return {
                "username":"%s_%s" % (provider, loginName),
                "first_name": "%s_%s" % (provider, loginName),
                "email": email if email else "%s@%s.com" % (loginName, provider)
                }
            pass
        else:
            return {}
   