package com.example.cades;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.simplereport.SimpleReport;

import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The verification summary as JSON, for scripts. Written by hand to keep
 * the fat jar free of a JSON library; the structure is small and flat.
 */
final class JsonReport {

    private JsonReport() {
    }

    static String of(CAdESLtVerifier.Result result) {
        SimpleReport simple = result.reports().getSimpleReport();
        String id = simple.getFirstSignatureId();

        Map<String, Object> json = new LinkedHashMap<>();
        json.put("level", result.level() == null ? null : result.level().toString());
        json.put("indication", result.indication() == null ? null : result.indication().name());
        json.put("subIndication", id == null || simple.getSubIndication(id) == null
                ? null : simple.getSubIndication(id).name());
        json.put("passed", result.isPassed());
        json.put("longTerm", result.isLongTerm());
        json.put("signatureIntact", result.isSignatureIntact());
        json.put("chainTrusted", result.isChainTrusted());
        json.put("qualification", id == null || simple.getSignatureQualification(id) == null
                ? null : simple.getSignatureQualification(id).getReadable());
        json.put("signingTime", id == null ? null : instant(simple.getSigningTime(id)));
        json.put("bestSignatureTime", id == null ? null : instant(simple.getBestSignatureTime(id)));
        json.put("signedBy", id == null ? null : simple.getSignedBy(id));

        SignatureWrapper signature = result.signatureWrapper();
        CertificateWrapper signingCertificate = signature == null ? null : signature.getSigningCertificate();
        json.put("signerSubject", signingCertificate == null ? null : signingCertificate.getCertificateDN());
        json.put("signerIssuer", signingCertificate == null ? null : signingCertificate.getCertificateIssuerDN());

        List<Object> timestamps = new ArrayList<>();
        if (id != null) {
            for (TimestampWrapper timestamp : result.reports().getDiagnosticData().getTimestampList(id)) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("type", timestamp.getType().name());
                entry.put("productionTime", instant(timestamp.getProductionTime()));
                entry.put("valid", timestamp.isSignatureValid() && timestamp.isMessageImprintDataIntact());
                timestamps.add(entry);
            }
        }
        json.put("timestamps", timestamps);

        List<Object> errors = new ArrayList<>();
        if (id != null) {
            for (Message message : simple.getAdESValidationErrors(id)) {
                errors.add(message.getValue());
            }
        }
        json.put("errors", errors);

        StringBuilder out = new StringBuilder();
        write(out, json);
        return out.toString();
    }

    private static String instant(Date date) {
        return date == null ? null : date.toInstant().toString();
    }

    private static void write(StringBuilder out, Object value) {
        switch (value) {
            case null -> out.append("null");
            case Boolean b -> out.append(b);
            case Number n -> out.append(n);
            case String s -> string(out, s);
            case Map<?, ?> map -> {
                out.append('{');
                boolean first = true;
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    if (!first) {
                        out.append(',');
                    }
                    first = false;
                    string(out, entry.getKey().toString());
                    out.append(':');
                    write(out, entry.getValue());
                }
                out.append('}');
            }
            case List<?> list -> {
                out.append('[');
                for (int i = 0; i < list.size(); i++) {
                    if (i > 0) {
                        out.append(',');
                    }
                    write(out, list.get(i));
                }
                out.append(']');
            }
            default -> string(out, value.toString());
        }
    }

    private static void string(StringBuilder out, String s) {
        out.append('"');
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }
}
