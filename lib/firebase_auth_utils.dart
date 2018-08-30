import 'dart:async';

import 'package:firebase_auth/firebase_auth.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_facebook_login/flutter_facebook_login.dart';
import 'package:google_sign_in/google_sign_in.dart';

final FirebaseAuth _auth = FirebaseAuth.instance;
final GoogleSignIn _googleSignIn = new GoogleSignIn();


/// Possible result statuses for a request to sign in using email address and password to Firebase
///
/// I was unable to find official documentation for these status codes - they were found through
/// experimentation.
enum FirebaseEmailSignInStatus {

  /// The sign in attempt succeeded
  ///
  /// Huzzah! This is the only status where the accompanying FirebaseUser in a FirebaseAuthResult
  /// will not be null.
  SUCCESS,


  /// No user with this email address exists with Firebase
  ///
  /// Invalid email addresses will not return this error, but return [ERROR_INVALID_EMAIL]
  ERROR_USER_NOT_FOUND,


  /// The email address supplied was null or blank
  ///
  /// Client side validation should prevent this from occurring. It is checked in functions
  /// below to prevent internal errors in the Android Firebase Authentication library
  ERROR_MISSING_EMAIL,


  /// The password supplied was null or blank
  ///
  /// Client side validation should prevent this from occurring. It is checked in functions
  /// below to prevent internal errors in the Android Firebase Authentication library
  ERROR_MISSING_PASSWORD,


  /// The supplied email address was not a valid email address
  ///
  /// To save time for users, it is typically easy to perform client-side regex testing of email
  /// addresses to alert users of invalid emails without needing to send a request to Firebase.
  ERROR_INVALID_EMAIL,


  /// Email entered is a valid account, but the supplied password is incorrect
  ///
  /// If the supplied password is below the minimum length of 6 characters for Firebase
  /// Authentication then this error is also returned (because the password is definitely incorrect)
  /// Client side validation should occur beforehand to prompt for passwords that are too short
  ///
  /// This error is also return when the email address used is actually tied to a social account,
  /// in which case no password will ever be correct
  ERROR_WRONG_PASSWORD,


  /// Any other error returned from Firebase Authentication
  ///
  /// Network timeouts also fall under this category. In this case, it is best to tell the user the
  /// request failed and they should check their network connection / try again later. Check the
  /// flutter logs to see the exact error printed.
  ERROR_UNKNOWN,

}

/// Possible result statuses for an attempt to sign in to Firebase using an external provider
///
/// In this util class, only Google and Facebook are currently implemented, but others are supported
/// by Firebase.
enum FirebaseSocialSignInStatus {

  /// The sign in attempt succeeded
  ///
  /// Huzzah! This is the only status where the accompanying FirebaseUser in a FirebaseAuthResult
  /// will not be null.
  SUCCESS,

  /// The request was cancelled by the user.
  ///
  /// Social sites typically launch a separate window / overlay window to allow the user to log in
  /// or select an account. If they close or back out of this window, this will be the result.
  CANCELLED,

}


enum FirebaseEmailSignUpStatus {

  /// The sign in attempt succeeded
  ///
  /// Huzzah! This is the only status where the accompanying FirebaseUser in a FirebaseAuthResult
  /// will not be null.
  SUCCESS,

  /// The email used was not correctly formatted
  ///
  /// Client side input validation using regex matching can be used to validate email addresses
  /// before sending to avoid this error code.
  ///
  /// Valid email address is the first check returned by Firebase (and will be the only result
  /// returned even if there are other issues like password length)
  ERROR_INVALID_EMAIL,


  /// The supplied email address value is null or blank
  ///
  /// This should ideally be caught by client-side validation. The Android Firebase Auth
  /// library will through an internal exception if the email address or password is missing,
  /// while the iOS library returns this status. For consistency, the helper functions below
  /// always perform the check first before invoking a native library.
  ERROR_MISSING_EMAIL,


  /// The password supplied is not sufficiently complex.
  ///
  /// Firebase Authentication with email and password currently requires a 6 character minimum
  /// password length. Password length should be validated client side to avoid this error.
  ///
  /// Weak password is the second check performed by firebase, and will be returned even if the
  /// email address is already in use
  ERROR_WEAK_PASSWORD,


  /// An account already exists using the requested sign-up email address
  ///
  /// The third check performed by Firebase. This error will be returned if the email address is
  /// already associated with an existing Firebase account, including Social site accounts.
  ///
  /// Unfortunately there does not seem to be sufficient information in the response to inform the
  /// user to try a particular social site instead to sign in with this email address (would there
  /// be any privacy implications in that case?)
  ///
  /// In this case the password is ignored. Attempting to sign up with the same email AND password
  /// as an existing account already uses will still result in this error, not a successful sign-in.
  ERROR_EMAIL_ALREADY_IN_USE,

}


class FirebaseAuthResult<T> {
  T status;
  FirebaseUser user;

  FirebaseAuthResult.Error({@required this.status});
  FirebaseAuthResult.Success({@required this.status, @required this.user});
}

/// Maps native error code strings to statuses
final emailSignInErrorCodes = <String, FirebaseEmailSignInStatus>{
  // Same error codes are returned by both iOS and Android
  'ERROR_WRONG_PASSWORD'  : FirebaseEmailSignInStatus.ERROR_WRONG_PASSWORD,
  'ERROR_USER_NOT_FOUND'  : FirebaseEmailSignInStatus.ERROR_USER_NOT_FOUND,
  'ERROR_INVALID_EMAIL'   : FirebaseEmailSignInStatus.ERROR_INVALID_EMAIL,
};

/// Maps native error code strings to statuses
final emailSignUpErrorCodes = <String, FirebaseEmailSignUpStatus> {
  // Same error codes are returned by both iOS and Android
  'ERROR_INVALID_EMAIL' : FirebaseEmailSignUpStatus.ERROR_INVALID_EMAIL,
  'ERROR_WEAK_PASSWORD': FirebaseEmailSignUpStatus.ERROR_WEAK_PASSWORD,
  'ERROR_EMAIL_ALREADY_IN_USE' : FirebaseEmailSignUpStatus.ERROR_EMAIL_ALREADY_IN_USE,
  'ERROR_MISSING_EMAIL'   : FirebaseEmailSignUpStatus.ERROR_MISSING_EMAIL,
};


class FirebaseAuthUtils {


  /// Sign a user up with an email address and password
  ///
  /// Due to differences in the native Firebase Authentication Android and iOS libraries, null or
  /// empty email/password validation is performed here.
  /// ERROR_EMAIL_MISSING is returned for null or empty email addresses
  /// ERROR_WEAK_PASSWORD is returned for a null or < 6 character password
  ///
  /// No client-side validation is performed that the email is correctly formatted. This should be
  /// performed as part of UI validation before submission.
  /// ERROR_INVALID_EMAIL will be returned by Firebase for invalid email formats
  ///
  /// ERROR_EMAIL_ALREADY_IN_USE is returned when the email is in use by an existing user
  ///
  /// Exceptions will be thrown under any other circumstances, including Network connectivity
  /// failure. Exception messages are intended for developer use only and are unlikely to be user
  /// friendly. Handle exceptions with a prompt to check network connectivity and retry.
  Future<FirebaseAuthResult<FirebaseEmailSignUpStatus>> signUpWithEmail(String email, String password) async {
    if (email == null || email?.length == 0) {
      return FirebaseAuthResult<FirebaseEmailSignUpStatus>.Error(
    status: FirebaseEmailSignUpStatus.ERROR_MISSING_EMAIL,
    );
    }
    if (password == null || (password?.length ?? 0) < 6) {
    return FirebaseAuthResult<FirebaseEmailSignUpStatus>.Error(
    status: FirebaseEmailSignUpStatus.ERROR_WEAK_PASSWORD,
    );
    }

    try {
    final user = await _auth.createUserWithEmailAndPassword(
    email: email,
    password: password,
    );
    assert(user != null);
    return FirebaseAuthResult<FirebaseEmailSignUpStatus>.Success(
    status: FirebaseEmailSignUpStatus.SUCCESS,
    user: user,
    );
    } catch (error) {
    if (error is PlatformException) {
    if (emailSignUpErrorCodes.containsKey(error.code)) {
    return FirebaseAuthResult<FirebaseEmailSignUpStatus>.Error(
    status: emailSignUpErrorCodes[error.code],
    );
    } else {
    throw "Unexpected Firebase Authentication exception for email sign up: $error";
    }
    } else {
    throw "Unexpected Firebase Authentication exception for email sign up: $error";
    }
    }
  }

  /// Sign a user in using an email address and password
  ///
  /// Due to differences in the native Firebase Authentication Android and iOS libraries, null or
  /// empty email/password validation is performed here.
  /// ERROR_MISSING_EMAIL is returned for null or empty email addresses
  /// ERROR_MISSING_PASSWORD is returned for a null or empty password
  ///
  /// No client-side validation is performed that the email is correctly formatted. This should be
  /// performed as part of UI validation before submission.
  /// ERROR_INVALID_EMAIL is returned by Firebase for invalid email formats
  ///
  /// ERROR_USER_NOT_FOUND is returned by Firebase when user does not have an account
  /// ERROR_WRONG_PASSWORD is returned by Firebase when password is incorrect
  ///
  /// Exceptions will be thrown under any other circumstances, including Network connectivity
  /// failure. Exception messages are intended for developer use only and are unlikely to be user
  /// friendly. Handle exceptions with a prompt to check network connectivity and retry.
  Future<FirebaseAuthResult<FirebaseEmailSignInStatus>> signInWithEmail(String email, String password) async {

    if (email == null || email?.length == 0) {
      return FirebaseAuthResult<FirebaseEmailSignInStatus>.Error(
    status: FirebaseEmailSignInStatus.ERROR_MISSING_EMAIL,
    );
    }
    if (password == null || password?.length == 0) {
    return FirebaseAuthResult<FirebaseEmailSignInStatus>.Error(
    status: FirebaseEmailSignInStatus.ERROR_MISSING_PASSWORD,
    );
    }

    try {
    final user = await _auth.signInWithEmailAndPassword(
    email: email,
    password: password,
    );
    assert(user != null);
    return FirebaseAuthResult<FirebaseEmailSignInStatus>.Success(
    status: FirebaseEmailSignInStatus.SUCCESS,
    user: user,
    );
    } catch (error) {
    if (error is PlatformException) {
    if (emailSignInErrorCodes.containsKey(error.code)) {
    return  FirebaseAuthResult<FirebaseEmailSignInStatus>.Error(
    status: emailSignInErrorCodes[error.code],
    );
    } else {
    throw "Unexpected Firebase Authentication exception for email sign-in: $error";
    }
    } else {
    throw "Unexpected Firebase Authentication exception for email sign-in: $error";
    }
    }
  }


  /// Perform sign in using a google account
  ///
  /// Cancelled status will be returned if cancelled by user
  ///
  /// Any other failure will result in a thrown exception
  Future<FirebaseAuthResult<FirebaseSocialSignInStatus>> signInWithGoogle() async {
    // Attempt to get the currently authenticated user
    GoogleSignInAccount currentUser = _googleSignIn.currentUser;
    if (currentUser != null) {
      // Sign out if already signed in so they can pick account again
      await _googleSignIn.signOut();
    }

    // Force the user to interactively sign in
    try {
      currentUser = await _googleSignIn.signIn();
    } catch (error) {
      throw "Unexpected Google sign-in exception: $error";
    }

    // If null is returned from Google sign in then user cancelled the operation
    if (currentUser == null) {
      return FirebaseAuthResult.Error(status: FirebaseSocialSignInStatus.CANCELLED);
    }

    // Authenticate with firebase using the Google sign-in token
    final GoogleSignInAuthentication auth = await currentUser.authentication;
    try {
      final FirebaseUser user = await _auth.signInWithGoogle(
        idToken: auth.idToken,
        accessToken: auth.accessToken,
      );
      return FirebaseAuthResult.Success(status: FirebaseSocialSignInStatus.SUCCESS, user: user);
    } catch(error) {
      throw "Unexpected Firebase Authentication exception for Google sign-in: $error";
    }
  }



  /// Perform sign in using a facebook account
  ///
  /// Cancelled status will be returned if cancelled by user
  ///
  /// Any other failure will result in a thrown exception
  Future<FirebaseAuthResult<FirebaseSocialSignInStatus>> signInWithFacebook() async {
    var facebookLogin = new FacebookLogin();
    var loggedIn = await facebookLogin.isLoggedIn;
    if (loggedIn) {
      // Sign out if already signed in so users can pick account again
      await facebookLogin.logOut();
    }

    FacebookLoginResult result;
    try {
      result = await facebookLogin.logInWithReadPermissions(['email']);
    } catch (error) {
      throw "Unexpected Facebook sign-in exception: $error";
    }

    switch(result.status) {
      case FacebookLoginStatus.loggedIn:
        FirebaseUser user;
        try {
          user = await _auth.signInWithFacebook(accessToken: result.accessToken.token);
        } catch (error) {
          throw "Unexpected Firebase Authentication exception for Facebook sign-in: $error";
        }
        return FirebaseAuthResult.Success(status: FirebaseSocialSignInStatus.SUCCESS, user: user);
      case FacebookLoginStatus.cancelledByUser:
        return FirebaseAuthResult.Error(status: FirebaseSocialSignInStatus.CANCELLED);
      case FacebookLoginStatus.error:
        throw "Unexpected Facebook sign in error response: ${result.errorMessage}";
      default:
        throw "Unexpected null result from Facebook sign-in";
    }
  }



  Future<String> getFireBaseIdToken() async {
    final FirebaseUser user = await _auth.currentUser();
    if (user == null)
      return null;
    return await user.getIdToken();
  }






  /// Sign out of any social service and then sign out of firebase authentication
  Future<Null> signOutOfAll() async {

    // Google
    await signOutOfGoogle();

    // Facebook
    await signOutOfFacebook();

    // Sign out with firebase
    await _auth.signOut();
  }

  /// Sign out of google only (not signed out of firebase)
  Future<Null> signOutOfGoogle() async {
    if (await _googleSignIn.isSignedIn()) {
      await _googleSignIn.signOut();
    }
  }

  /// Sign out of facebook only (not signed out of firebase)
  Future<Null> signOutOfFacebook() async {
    var facebookLogin = new FacebookLogin();
    if (await facebookLogin.isLoggedIn) {
      await FacebookLogin().logOut();
    }
  }

}



