//
//  CerPinsky.swift
//

import WebKit
import Alamofire

// protocol that delegates need to implement
protocol ChallengeResultDelegate: class {
    func sessionDelegateDidCompleteChallenge(_ sessionDelegate: CerPinsky)
    func sessionDelegateDidFailChallenge(_ sessionDelegate: CerPinsky)
}

/// The purpose of this class is to centralize certificate pinning logic
/// Currently it is able to handle certificate pinning for:
/// - WKWebView
/// - UIWebView
/// - Alamofire (or network libraries using Alamofire SessionManager)
class CerPinsky: SessionDelegate {
    
    typealias ChallengeCompletion = (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    
    // MARK: - Constants
    
    let policyManager: ServerTrustPolicyManager!

    // MARK: - Variables
    
    lazy var sessionManager: SessionManager = {
        return SessionManager(configuration: .default,
                              delegate: self,
                              serverTrustPolicyManager: policyManager)
    }()

    var delegate: ChallengeResultDelegate?
    
    
    /// Initialize CerPinsky with policies
    ///
    /// - Parameter policies: a dictionary of domain keys and policy values
    init(policies: [String: ServerTrustPolicy]) {
        
        policyManager = ServerTrustPolicyManager(policies: policies)
        
        super.init()
        
        // provide a custom challenge handling block for individual tasks
        // since tasks have their own delegate, it will not call the session challenge
        taskDidReceiveChallengeWithCompletion = { session, _, challenge, completion in
            self.urlSession(session, didReceive: challenge, completionHandler: completion)
        }
    }
    
    // MARK: - SessionDelegate Override
    
    override func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping ChallengeCompletion) {
        super.urlSession(session, didReceive: challenge, completionHandler: { disposition, credential in
            self.sessionWillTryDisposition(disposition)
            completionHandler(disposition, credential)
        })
    }
    
    // MARK: - Private
    
    /// Method to handle authentication challenges
    ///
    /// - Parameters:
    ///   - challenge: The challenge
    ///   - completionHandler: The completion handler
    private func handleChallenge(challenge: URLAuthenticationChallenge, completionHandler: @escaping ChallengeCompletion) {
        var disposition: URLSession.AuthChallengeDisposition = .performDefaultHandling
        var credential: URLCredential?
        
        // perform certificate validation
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            let host = challenge.protectionSpace.host
            
            // if we have a policy for this host,
            // and we have the ssl transactional state
            if
                let serverTrustPolicy = policyManager.serverTrustPolicy(forHost: host),
                let serverTrust = challenge.protectionSpace.serverTrust
            {
                // if we can evaluate ssl state with the policy
                if serverTrustPolicy.evaluate(serverTrust, forHost: host) {
                    // create credential from evaluated trust
                    disposition = .useCredential
                    credential = URLCredential(trust: serverTrust)
                } else {
                    // otherwise cancel the challenge
                    // (we want to enforce pinning for the domains that have a policy)
                    disposition = .cancelAuthenticationChallenge
                }
            }
        }
        
        // notify delegate of the chosen disposition
        sessionWillTryDisposition(disposition)
        // respond to the challenge
        completionHandler(disposition, credential)
    }
    
    private func sessionWillTryDisposition(_ disposition: URLSession.AuthChallengeDisposition) {
        switch disposition {
        case .cancelAuthenticationChallenge:
            // cancelAuthenticationChallenge means there was a policy for this domain,
            // and the evaluation failed, so we consider this a failure.
            delegate?.sessionDelegateDidFailChallenge(self)
        default:
            // performDefaultHandling is considered a completed challenge,
            // since there was no policy, we don't care about pinning
            delegate?.sessionDelegateDidCompleteChallenge(self)
        }
    }
}

// MARK: - UIWebViewDelegate Conformance
extension CerPinsky: UIWebViewDelegate {}

// MARK: - WKNavigationDelegate Conformance
extension CerPinsky: WKNavigationDelegate {
    func webView(_ webView: WKWebView, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping ChallengeCompletion) {
        handleChallenge(challenge: challenge, completionHandler: completionHandler)
    }
}
