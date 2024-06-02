import { decode } from 'jsonwebtoken'
import jsonwebtoken from 'jsonwebtoken'
import winston from 'winston'

function createLogger(loggerName) {
  return winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    defaultMeta: { name: loggerName },
    transports: [new winston.transports.Console()]
  })
}

const logger = createLogger('utils')
/**
 * Parse a JWT token and return a user id
 * @param jwtToken JWT token to parse
 * @returns a user id from the JWT token
 */
export function parseUserId(jwtToken) {
  const decodedJwt = decode(jwtToken)
  return decodedJwt.sub
}

const certificate = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIJEfJbrJKTxxENMA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNV
BAMTIWRldi1hN2h2eGQxZ2JidWpmODJuLnVzLmF1dGgwLmNvbTAeFw0yNDA1MjYx
NTMxMDJaFw0zODAyMDIxNTMxMDJaMCwxKjAoBgNVBAMTIWRldi1hN2h2eGQxZ2Ji
dWpmODJuLnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAKoVTV7uClDlYafy6joLzUprDg06RetpgT7s9EWtBuFqAMA0VTrEz11FUk6V
Fc8ILYjNC+wz7AJHiMHEXmYwc2SgBzPXhIU+wwhF/iWvi7sr+Zm9qtwR81UW8w1D
0WDCNC1xZz5CV4rt5kvuc0bQMjz42Ji0zbXcrf4lYa92kXm7krPa5As5VyxlTJkq
5Yfcacxf06HbuP8T+JB+6xuE8bba2JXsdhD9yJhGJxyfmei4JB04LXN3DmYIRtQG
Wr0G6kTPpbYRQZaLIRDMbLKpEfj9OZnfF7v8Upbierc9e36DfbJdYHYwW1m0AGxc
IstDR9RWJqvghVkrfmg6TSWWqpUCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUloMRsuUDsxYgEojdPJU+Wzo7p+YwDgYDVR0PAQH/BAQDAgKEMA0G
CSqGSIb3DQEBCwUAA4IBAQCQHA6z1A28X3MshHeAAIWE7VC63V1nN0BLonXfhXRy
xIihlNUqiXHsA17C/TKF+IuQF0PFzugENrPeUx851bk8vNcKN1rhvwhDCHzzNob6
UJ+3fUR2rOlOwUnt9Jt+Xt8W+4930FzpYSgzFtrOukMveOYAAF9wrmomX73YXwIr
wj/sVqwZx0nsOHcQdsxq/xFX9ulrrvCNEwiAMzNleMGccSWGOFwQb+L2eqfMN70Y
snAOh6xUlUnGH6gex/KU6QU9L0kcMlwYfH2JqtD/xJs538dFDXNCdvEmZj1XCwz8
sISKC4ukd7q1hOzfxI3FkYMesk0aPOWzUsagKvNr4agf
-----END CERTIFICATE-----`

const jwksUrl = 'https://test-endpoint.auth0.com/.well-known/jwks.json'

export async function handler(event) {
  try {
    const jwtToken = await verifyToken(event.authorizationToken)

    console.log('jwtToken', jwtToken)
    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader) {
  const token = getToken(authHeader)
  // TODO: Implement token verification
  return jsonwebtoken.verify(token, certificate, { algorithms: ['RS256'] })
}

function getToken(authHeader) {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
