package cades.de.exception;

import cades.de.CadesSign;

public class ApplicationException extends RuntimeException {

	private static final long serialVersionUID = 8737702296922693068L;

	public ApplicationException() {
		super();
		CadesSign.setFailed(true);
	}

	public ApplicationException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
		CadesSign.setFailed(true);
	}

	public ApplicationException(String message, Throwable cause) {
		super(message, cause);
		CadesSign.setFailed(true);
	}

	public ApplicationException(String message) {
		super(message);
		CadesSign.setFailed(true);
	}

	public ApplicationException(Throwable cause) {
		super(cause);
		CadesSign.setFailed(true);
	}

}
