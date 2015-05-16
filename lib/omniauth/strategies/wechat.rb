require "omniauth-oauth2"

module OmniAuth
  module Strategies
    class Wechat < OmniAuth::Strategies::OAuth2
      WECHAT_BROWSER_STRING = 'MicroMessenger'
      option :name, "wechat"

      option :client_options, {
        site:          "https://api.weixin.qq.com",
        authorize_url: "https://open.weixin.qq.com/connect/oauth2/authorize#wechat_redirect",
        token_url:     "/sns/oauth2/access_token",
        token_method:  :get
      }

      option :authorize_params, {scope: "snsapi_login"}

      option :token_params, {parse: :json}

      # unionid is uniquely identifiable across multiple apps for the same WeChat merchant account 
      # while the openid is different between "website" and "weixin merchant payment"
      uid do
        raw_info['unionid'] || raw_info['openid']
      end

      info do
        {
          nickname:   raw_info['nickname'],
          sex:        raw_info['sex'],
          province:   raw_info['province'],
          city:       raw_info['city'],
          country:    raw_info['country'],
          headimgurl: raw_info['headimgurl']
        }
      end

      extra do
        {raw_info: raw_info}
      end

      def request_phase
        params = client.auth_code.authorize_params.merge(redirect_uri: callback_url).merge(authorize_params)
        params["appid"] = params.delete("client_id")
        redirect augment_client_options(client).authorize_url(params)
        .tap{|url| puts "url generated is #{url}"}
      end

      def raw_info
        @uid ||= access_token["openid"]
        @raw_info ||= begin
          access_token.options[:mode] = :query
          if %w(snsapi_userinfo snsapi_login).include?(access_token["scope"])
            response = access_token.get("/sns/userinfo", :params => {"openid" => @uid}, parse: :text)
            @raw_info = JSON.parse(response.body.gsub(/[\u0000-\u001f]+/, ''))
          else
            @raw_info = {"openid" => @uid }
          end
          .tap {|raw| puts "raw info received is #{raw}"}
        end
      end

      protected
      def build_access_token
        params = {
          'appid' => client.id, 
          'secret' => client.secret,
          'code' => request.params['code'],
          'grant_type' => 'authorization_code' 
          }.merge(token_params.to_hash(symbolize_keys: true))
        client.get_token(params, deep_symbolize(options.auth_token_params))
      end

      private
      def augment_client_options(auth_client)
        unless is_wechat_browser?
          auth_client.options[:authorize_url] = 'https://open.weixin.qq.com/connect/qrconnect#wechat_redirect'
        end
        auth_client
      end

      def is_wechat_browser?
        Rack::Request.new(@env).user_agent =~ Regexp.new(WECHAT_BROWSER_STRING)
      end

    end
  end
end
