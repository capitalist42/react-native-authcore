import { NativeModules } from 'react-native'
import url from 'url'

import Agent from './agent'
import { apply } from '../utils/whitelist'

const { Authcore } = NativeModules

const bundleIdentifier = Authcore.bundleIdentifier

export default class WebAuth {
  constructor (auth) {
    if (!auth) {
      throw new Error('Auth instance is not found. Please provide it.')
    }
    this.auth = auth
    this.agent = new Agent()
    this.client = auth.client
  }

  signin (options = {}) {
    return new Promise((resolve, reject) => {
      this.agent.newTransaction().then(({ state, verifier, ...defaults }) => {
        // return new Promise((resolve, reject) => {
        // TODO: Not to fix the redirect URI
        const redirectURI = `${bundleIdentifier}://`
        const expectedState = state
        const payloadForAuthorizeUrl = apply({
          parameters: {
            redirectURI: { required: true, toName: 'redirectURI' },
            responseType: { required: true, toName: 'responseType' },
            state: { required: true },
            clientId: { required: false, toName: 'clientId' },
            logo: { required: false },
            company: { required: false },
            primaryColour: { required: false },
            successColour: { required: false },
            dangerColour: { required: false },
            socialLoginPaneOption: { required: false, toName: 'socialLoginPaneOption' },
            socialLoginPaneStyle: { required: false, toName: 'socialLoginPaneStyle' },
            buttonSize: { required: false, toName: 'buttonSize' },
            language: { required: false }
          },
          whitelist: false
        }, {
          ...defaults,
          responseType: 'code',
          redirectURI: redirectURI,
          state: expectedState,
          clientId: this.client.clientId,
          company: this.client.company,
          logo: this.client.logo,
          primaryColour: this.client.primaryColour,
          successColour: this.client.successColour,
          dangerColour: this.client.dangerColour,
          socialLoginPaneOption: this.client.socialLoginPaneOption,
          socialLoginPaneStyle: this.client.socialLoginPaneStyle,
          buttonSize: this.client.buttonSize,
          language: this.client.language
        })
        const initialScreen = this.client.initialScreen
        const authorizeUrl = this.client.url(`/widgets/${initialScreen}`, payloadForAuthorizeUrl)
        this.agent.show(authorizeUrl, false).then((redirectUrl) => {
          if (!redirectURI) {
            throw new Error('redirectURI cannot be empty. Please provide the value')
          }
          const query = url.parse(redirectUrl, true).query
          const { code, state: resultState } = query
          const payloadForTokens = apply({
            parameters: {
              token: { required: true },
              verifier: { required: true, toName: 'code_verifier' }
            }
          }, {
            token: code,
            verifier: verifier
          })
          if (expectedState !== resultState) {
            throw new Error('Invalid state')
          }
          // Exchange to get tokens
          this.client.post('/api/auth/tokens', {
            ...payloadForTokens,
            grant_type: 'AUTHORIZATION_TOKEN'
          })
            .then(async (response) => {
              const currentUser = await this.auth.userInfo({
                token: response.json.access_token
              })
              const resp = {
                accessToken: response.json.access_token,
                refreshToken: response.json.refresh_token,
                idToken: response.json.id_token,
                currentUser: currentUser
              }
              resolve(resp)
            })
            .catch((err) => reject(err))
        })
          // For `show` function, this will happen if user cancel the prompt in iOS platform
          .catch((err) => reject(err))
      })
        // For `newTransaction` function, for backup usage as this should not be happened
        .catch((err) => reject(err))
    })
  }
}
