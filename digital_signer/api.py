import frappe
import base64
from frappe.utils.pdf import get_pdf
import os
from io import BytesIO
from pyhanko.sign import signers, fields, validation
from pyhanko.sign.signers import PdfSigner, PdfSignatureMetadata
from pyhanko.sign.fields import SigFieldSpec, append_signature_field
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.stamp import QRStampStyle
from PyPDF2 import PdfReader
import ast
from frappe import ValidationError
from pyhanko.sign.timestamps import HTTPTimeStamper
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from asn1crypto import pem, x509 as asn1_x509
import json
from PIL import Image

@frappe.whitelist()
def generate_invoice_pdf(doctype,docname):
    """Generate Sales Invoice PDF and return as base64"""
    try:
        doc = frappe.get_doc(doctype, docname)  # Get the Sales Invoice
        html = frappe.get_print(doctype, docname, print_format="Standard")
        pdf_data = get_pdf(html)

        # Convert PDF to base64
        pdf_base64 = base64.b64encode(pdf_data).decode("utf-8")
        return {"pdf": pdf_base64, "filename": f"{docname}.pdf"}

    except Exception as e:
        frappe.log_error(f"Error generating PDF: {str(e)}", "PDF Generation Error")
        return {"error": str(e)}



# @frappe.whitelist()
# def sign_sales_invoice_pdf(doctype, sales_invoice_name, print_format_name=None):
#     try:
#         # Load Sales Invoice PDF
#         pdf_content = frappe.get_print(
#             doctype,
#             sales_invoice_name,
#             print_format=print_format_name or "Digital Sign",
#             as_pdf=True
#         )

#         # Load DSC from Document Sign Setting
#         digi = frappe.get_doc("Document Sign Setting")
#         actual_password = digi.get_password('dsc_password')

#         pfx_path = frappe.get_site_path(digi.pfx_file.lstrip("/"))
#         if not os.path.exists(pfx_path):
#             frappe.throw(f"PFX file not found: {pfx_path}")

#         # Load CA-issued DSC
#         signer = signers.SimpleSigner.load_pkcs12(
#             pfx_path,
#             passphrase=actual_password.encode()
#         )

#         # # TSA for long-term validity
#         # tsa_url = "http://tsa1.emudhra.com"  # or tsa2.emudhra.com
#         # timestamper = HTTPTimeStamper(tsa_url)

#         # Prepare PDF for signing
#         input_pdf = BytesIO(pdf_content)
#         num_pages = len(PdfReader(input_pdf).pages)
#         input_pdf.seek(0)

#         reader = IncrementalPdfFileWriter(input_pdf)
#         box = ast.literal_eval(digi.location) if digi.location else (345, 50, 545, 100)
#         # Add signature field on last page
#         sig_field_spec = SigFieldSpec(
#             sig_field_name="Signature_Last_Page",
#             box=box,
#             on_page=num_pages - 1
#         )
#         append_signature_field(reader, sig_field_spec)

#         # Signature metadata
#         signature_meta = PdfSignatureMetadata(
#             field_name="Signature_Last_Page",
#             reason=f"Digitally signed on {doctype}",
#             location=digi.sign_address or "India"
#         )

#         # Output buffer
#         output = BytesIO()

#         # Sign PDF with TSA
#         PdfSigner(
#             signature_meta,
#             signer=signer,
#             stamp_style=QRStampStyle(stamp_text="For: %(signer)s\nTime: %(ts)s"),
#         ).sign_pdf(reader, output)

#         # Attach signed PDF to Frappe
#         file_doc = frappe.get_doc({
#             "doctype": "File",
#             "file_name": f"{sales_invoice_name}-signed.pdf",
#             "is_private": 1,
#             "content": output.getvalue(),
#         })
#         file_doc.insert(ignore_permissions=True)

#         return frappe.utils.get_url(file_doc.file_url)
#     except Exception as e:
#         frappe.log_error(frappe.get_traceback(), f"{doctype} Digital Sign Error")
#         frappe.msgprint("Error log created.")
#         frappe.throw("You entered an incorrect password in Document Sign Setting, or the PFX file is invalid. Please check the error log for more details.")




@frappe.whitelist()
def sign_sales_invoice_pdfs(doctype,sales_invoice_name, print_format_name=None, entered_password=None, multiple_page = None):
    """
    Generates the Sales Invoice PDF, digitally signs it page by page, and attaches it to the Sales Invoice.
    """
    sales_invoice = frappe.get_doc(doctype, sales_invoice_name)
    pdf_content = frappe.get_print(
        doctype,
        sales_invoice_name,
        print_format=print_format_name or "Digital Sign",
        as_pdf=True
    )

    # Load digital signing configuration
    digi = frappe.get_doc("Document Sign Setting")
    actual_password = digi.get_password('dsc_password')
    # # Optional: Check entered password
    # if entered_password != actual_password:
    #     frappe.throw("Password is wrong.")

    # Load signer from .pfx file
    if digi.pfx_file_use:
        pfx = digi.pfx_file
        if not pfx:
            frappe.throw("PFX not uploaded in Document Sign Setting.")
        pfx_file_path = frappe.get_site_path(digi.pfx_file.lstrip("/"))

        if not os.path.exists(pfx_file_path):
            frappe.throw(f"PFX file not found: {pfx_file_path}")

        signer = signers.SimpleSigner.load_pkcs12(
            pfx_file_path,
            signature_mechanism=None,
            passphrase=actual_password.encode()
        )

    # Load signer from certificate and private key
    else:
        cert = digi.certificate
        pvt = digi.private_key

        if not cert or not pvt:
            frappe.throw("Private Key or Certificate not uploaded in Document Sign Setting.")

        cert_path = frappe.get_site_path(cert.lstrip("/"))
        key_path = frappe.get_site_path(pvt.lstrip("/"))

        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            frappe.throw("Certificate or Private Key file not found on server.")

        signer = signers.SimpleSigner.load(
            key_path,
            cert_path
        )


    # Add PDF signing logic here if needed.


    # Get page count
    input_pdf = BytesIO(pdf_content)
    num_pages = len(PdfReader(input_pdf).pages)
    input_pdf.seek(0)
    signed_pdf_io = input_pdf
    logo_path = frappe.get_site_path(digi.logo.lstrip("/")) if digi.get("logo") else None
    if logo_path and os.path.exists(logo_path):
        logo = Image.open(logo_path).convert("RGBA")
        logo.thumbnail((120, 120))  # scale to fit
    else:
        logo = None
    if int(multiple_page or 0) == 1:
        reader = IncrementalPdfFileWriter(input_pdf)
        #frappe.throw(f"hello {num_pages} and {multiple_page}")
        #frappe.throw(f'hello {num_pages}")
        #num_pages = len(reader.root['/Pages'].get_object()['/Kids'])

        for i in range(num_pages):
            signed_pdf_io.seek(0)
            reader = IncrementalPdfFileWriter(signed_pdf_io)
            output = BytesIO()

            sig_field_spec = SigFieldSpec(
                sig_field_name=f"Signature_Page_{i+1}",
                box=(345, 50, 545, 100),
                on_page=i
            )
            append_signature_field(reader, sig_field_spec)
            signer_display = digi.get("sign_address") or getattr(sales_invoice, "company", "Signer")
            stamp_text = f"Digitally Signed by\n{signer_display}\nTime: %(ts)s"
            signature_meta = PdfSignatureMetadata(
                field_name=sig_field_spec.sig_field_name,
                reason=f"Digitally signed on {doctype}",
                location=digi.sign_address or "India"
            )
            tsa_url = "http://timestamp.digicert.com"  # replace with eMudhra’s TSA
            timestamper = HTTPTimeStamper(tsa_url)
            pdf_signer = PdfSigner(
                signature_meta,
                signer=signer,
                stamp_style=QRStampStyle(
                    stamp_text=stamp_text
                ),
                timestamper=timestamper
            )

            pdf_signer.sign_pdf(
                reader,
                output=output,
                appearance_text_params={
                    'url': digi.url
                }
            )

            signed_pdf_io = output
    else:
        # Sign only the last page
        reader = IncrementalPdfFileWriter(input_pdf)
        #frappe.throw(f"{num_pages} and {multiple_page}")
        #num_pages = len(reader.root['/Pages'].get_object()['/Kids'])
        #frappe.throw(f'hello Lucky {num_pages}")
        output = BytesIO()

        sig_field_spec = SigFieldSpec(
            sig_field_name="Signature_Last_Page",
            box=(345, 50, 545, 100),
            on_page=num_pages - 1
        )
        append_signature_field(reader, sig_field_spec)

        signature_meta = PdfSignatureMetadata(
            field_name=sig_field_spec.sig_field_name,
            reason=f"Digitally signed on {doctype}",
            location=digi.sign_address or "India"
        )
        signer_display = digi.get("sign_address") or getattr(sales_invoice, "company", "Signer")
        stamp_text = f"Digitally Signed by\n{signer_display}\nTime: %(ts)s"
        pdf_signer = PdfSigner(
            signature_meta,
            signer=signer,
            stamp_style=QRStampStyle(
                stamp_text=stamp_text
            )
        )

        pdf_signer.sign_pdf(
            reader,
            output=output,
            appearance_text_params={
                'url': digi.url
            }
        )

        signed_pdf_io = output

    # Attach signed PDF to the document
    file_doc = frappe.get_doc({
        "doctype": "File",
        "file_name": f"{sales_invoice.name}-signed.pdf",
        "is_private": 1,
        "content": signed_pdf_io.getvalue(),
    })



    return f"{frappe.utils.get_url(file_doc.file_url)}"

@frappe.whitelist()
def validate_signed_pdf(file_url: str = None, file_name: str = None) -> str:
    """
    Validate a PDF's digital signatures (integrity, DocMDP/certification,
    RFC-3161 timestamp presence/validity). Returns JSON.
    One of file_url or file_name (File doctype name) is required.
    """
    if not file_url and not file_name:
        frappe.throw(_("Pass either file_url or file_name"))

    # Fetch file content from ERPNext "File" doctype or path
    if file_name:
        fdoc = frappe.get_doc("File", file_name)
        content = fdoc.get_content()
        display_name = fdoc.file_name
    else:
        # file_url like /private/files/XYZ.pdf
        file_path = frappe.get_site_path(file_url.lstrip("/"))
        with open(file_path, "rb") as fh:
            content = fh.read()
        display_name = file_url.split("/")[-1]

    pdf_bytes = BytesIO(content)

    # --- Basic validation (integrity, signature correctness, timestamps) ---
    # If you also want chain/revocation checks, see the "Trust & Revocation" notes below.
    # You can pass `validation_context=vc` into validate_pdf(...) when you configure it.

    # Enforce that signatures used for certification have the right key usage (recommended)
    key_usage = KeyUsageConstraints(key_cert_sign=False, digital_signature=True, non_repudiation=True)

    # validate_pdf returns an iterator over results (one per signature, newest first)
    results = list(validate_pdf(pdf_bytes, key_usage_constraints=key_usage))

    out = {
        "file": display_name,
        "signature_count": len(results),
        "signatures": []
    }

    for idx, res in enumerate(results, start=1):
        # res is a PdfSignatureStatus
        sig_info = {}

        # Basic integrity / cryptographic validity
        sig_info["ok"] = bool(getattr(res, "bottom_line", False))  # overall verdict
        sig_info["intact"] = bool(getattr(res, "modification_level", None) in (None, "MODIFICATION_LEVEL_NONE"))

        # Modification info (if available)
        ml = getattr(res, "modification_level", None)
        sig_info["modification_level"] = str(ml) if ml is not None else None

        # Signer info (CN/subject)
        signer_subject = None
        try:
            signer_subject = res.signer_report.signer_cert.subject.human_friendly
        except Exception:
            signer_subject = None
        sig_info["signer_subject"] = signer_subject

        # Signing time (claimed vs timestamped)
        claimed_time = None
        try:
            claimed_time = getattr(res, "signing_time", None)
            if claimed_time:
                claimed_time = claimed_time.isoformat()
        except Exception:
            pass
        sig_info["claimed_signing_time"] = claimed_time

        # DocMDP / Certification (whether this signature certified the doc)
        try:
            docmdp = res.docmdp_ok
            sig_info["docmdp_ok"] = bool(docmdp)
            # Permissions, if exposed
            perms = getattr(res, "docmdp_permissions", None)
            sig_info["docmdp_permissions"] = str(perms) if perms is not None else None
        except Exception:
            sig_info["docmdp_ok"] = None
            sig_info["docmdp_permissions"] = None

        # Timestamp token
        ts = getattr(res, "timestamp_validity", None)
        if ts is not None:
            # timestamp_validity has .valid and .signing_time (TSA time)
            tsa_valid = bool(getattr(ts, "valid", False))
            tsa_time = getattr(ts, "signing_time", None)
            sig_info["timestamp"] = {
                "present": True,
                "valid": tsa_valid,
                "tsa_time": tsa_time.isoformat() if tsa_time else None,
            }
        else:
            sig_info["timestamp"] = {"present": False, "valid": False, "tsa_time": None}

        # Certification chain status (only if you configure a VC; see notes)
        try:
            chain_ok = getattr(res, "trust_established", None)
            sig_info["trust_chain_ok"] = bool(chain_ok) if chain_ok is not None else None
        except Exception:
            sig_info["trust_chain_ok"] = None

        out["signatures"].append(sig_info)

    return json.dumps(out, default=str)
# @frappe.whitelist()
# def sign_sales_invoice_pdf(doctype, sales_invoice_name, print_format_name=None, entered_password=None, multiple_page=None, page_range=None):
#     try:
#         sales_invoice = frappe.get_doc(doctype, sales_invoice_name)
#         pdf_content = frappe.get_print(
#             doctype,
#             sales_invoice_name,
#             print_format=print_format_name or "Digital Sign",
#             as_pdf=True
#         )

#         digi = frappe.get_doc("Document Sign Setting")
#         actual_password = digi.get_password('dsc_password')
#         # if entered_password != actual_password:
#         #     frappe.throw("Password is wrong.")

#         # Load signer
#         if digi.pfx_file_use:
#             pfx = digi.pfx_file
#             if not pfx:
#                 frappe.throw("PFX not uploaded in Document Sign Setting.")
#             pfx_file_path = frappe.get_site_path(digi.pfx_file.lstrip("/"))
#             if not os.path.exists(pfx_file_path):
#                 frappe.throw(f"PFX file not found: {pfx_file_path}")
#             try:
#                 signer = signers.SimpleSigner.load_pkcs12(
#                     pfx_file_path,
#                     passphrase=actual_password.encode()
#                 )
#             except Exception:
#                 frappe.throw("Incorrect password for the DSC file.")
#         else:
#             cert = digi.certificate
#             pvt = digi.private_key

#             if not cert or not pvt:
#                 frappe.throw("Private Key or Certificate not uploaded in Document Sign Setting.")
#             cert_path = frappe.get_site_path(digi.certificate.lstrip("/"))
#             key_path = frappe.get_site_path(digi.private_key.lstrip("/"))
#             if not os.path.exists(cert_path) or not os.path.exists(key_path):
#                 frappe.throw("Certificate or Private Key file not found on server.")
#             signer = signers.SimpleSigner.load(key_path, cert_path)

#         # Read and count pages
#         input_pdf = BytesIO(pdf_content)
#         reader = PdfReader(input_pdf)
#         num_pages = len(reader.pages)
#         input_pdf.seek(0)

#         def parse_page_range(page_range_str, total_pages):
#             result = set()
#             if not page_range_str:
#                 return []
#             parts = page_range_str.split(',')
#             for part in parts:
#                 if '-' in part:
#                     start, end = part.split('-')
#                     start, end = int(start.strip()) - 1, int(end.strip()) - 1
#                     result.update(range(start, end + 1))
#                 else:
#                     result.add(int(part.strip()) - 1)
#             return sorted(p for p in result if 0 <= p < total_pages)

#         signed_pdf_io = input_pdf

#         if int(multiple_page or 0) == 1:
#             pages_to_sign = list(range(num_pages))
#         elif page_range:
#             pages_to_sign = parse_page_range(page_range, num_pages)
#         else:
#             pages_to_sign = [num_pages - 1]

#         for i, page_num in enumerate(pages_to_sign):
#             signed_pdf_io.seek(0)
#             reader = IncrementalPdfFileWriter(signed_pdf_io)
#             output = BytesIO()
#             box = ast.literal_eval(digi.location) if digi.location else (345, 50, 545, 100)
#             sig_field_spec = SigFieldSpec(
#                 sig_field_name=f"Signature_Page_{page_num + 1}",
#                 box=box,
#                 on_page=page_num
#             )
#             append_signature_field(reader, sig_field_spec)

#             signature_meta = PdfSignatureMetadata(
#                 field_name=sig_field_spec.sig_field_name,
#                 reason=f"Digitally signed on {doctype}",
#                 location=digi.sign_address or "India",
#                 md_algorithm='sha256',
#                 certify=True,  # This enables DocMDP
#                 docmdp_permissions=DocMDPAccessPermissions.NO_CHANGES
#             )

#             pdf_signer = PdfSigner(
#                 signature_meta,
#                 signer=signer,
#                 stamp_style=QRStampStyle(
#                     stamp_text="For: %(signer)s\nTime: %(ts)s"
#                 )
#             )

#             pdf_signer.sign_pdf(
#                 reader,
#                 output=output,
#                 appearance_text_params={'url': digi.url}
#             )

#             signed_pdf_io = output

#         # Attach the signed PDF
#         file_doc = frappe.get_doc({
#             "doctype": "File",
#             "file_name": f"{sales_invoice.name}-signed.pdf",
#             "is_private": 1,
#             "content": signed_pdf_io.getvalue(),
#         })
#         file_doc.insert(ignore_permissions=True)

#         return f"{frappe.utils.get_url(file_doc.file_url)}"


#     except ValidationError:
#         raise
#     except Exception as e:
#         frappe.log_error(frappe.get_traceback(), f"{doctype} Digital Sign Error")
#         frappe.msgprint("Error log created.")
#         frappe.throw("You entered an incorrect password in Document Sign Setting, or the PFX file is invalid. Please check the error log for more details.")

# @frappe.whitelist()
# def sign_sales_invoice_pdf(doctype, sales_invoice_name, print_format_name=None, entered_password=None, multiple_page=None, page_range=None):
#     try:
#         sales_invoice = frappe.get_doc(doctype, sales_invoice_name)
#         pdf_content = frappe.get_print(
#             doctype,
#             sales_invoice_name,
#             print_format=print_format_name or "Digital Sign",
#             as_pdf=True
#         )

#         digi = frappe.get_doc("Document Sign Setting")
#         actual_password = digi.get_password('dsc_password')

#         # Load signer
#         if digi.pfx_file_use:
#             pfx = digi.pfx_file
#             if not pfx:
#                 frappe.throw("PFX not uploaded in Document Sign Setting.")
#             pfx_file_path = frappe.get_site_path(digi.pfx_file.lstrip("/"))
#             if not os.path.exists(pfx_file_path):
#                 frappe.throw(f"PFX file not found: {pfx_file_path}")
#             try:
#                 signer = signers.SimpleSigner.load_pkcs12(
#                     pfx_file_path,
#                     passphrase=actual_password.encode(),
#                 )
#             except Exception:
#                 frappe.throw("Incorrect password for the DSC file.")
#         else:
#             cert = digi.certificate
#             pvt = digi.private_key
#             if not cert or not pvt:
#                 frappe.throw("Private Key or Certificate not uploaded in Document Sign Setting.")
#             cert_path = frappe.get_site_path(digi.certificate.lstrip("/"))
#             key_path = frappe.get_site_path(digi.private_key.lstrip("/"))
#             if not os.path.exists(cert_path) or not os.path.exists(key_path):
#                 frappe.throw("Certificate or Private Key file not found on server.")
#             signer = signers.SimpleSigner.load(key_path, cert_path)

#         # Read and count pages
#         input_pdf = BytesIO(pdf_content)
#         reader = PdfReader(input_pdf)
#         num_pages = len(reader.pages)
#         input_pdf.seek(0)

#         def parse_page_range(page_range_str, total_pages):
#             result = set()
#             if not page_range_str:
#                 return []
#             parts = page_range_str.split(',')
#             for part in parts:
#                 if '-' in part:
#                     start, end = part.split('-')
#                     start, end = int(start.strip()) - 1, int(end.strip()) - 1
#                     result.update(range(start, end + 1))
#                 else:
#                     result.add(int(part.strip()) - 1)
#             return sorted(p for p in result if 0 <= p < total_pages)

#         signed_pdf_io = input_pdf

#         if int(multiple_page or 0) == 1:
#             pages_to_sign = list(range(num_pages))
#         elif page_range:
#             pages_to_sign = parse_page_range(page_range, num_pages)
#         else:
#             pages_to_sign = [num_pages - 1]

#         for i, page_num in enumerate(pages_to_sign):
#             signed_pdf_io.seek(0)
#             writer = IncrementalPdfFileWriter(signed_pdf_io)
#             output = BytesIO()

#             box = ast.literal_eval(digi.location) if digi.location else (345, 50, 545, 100)
#             sig_field_spec = SigFieldSpec(
#                 sig_field_name=f"Signature_Page_{page_num + 1}",
#                 box=box,
#                 on_page=page_num
#             )
#             append_signature_field(writer, sig_field_spec)

#             signature_meta = signers.PdfSignatureMetadata(
#                 field_name=sig_field_spec.sig_field_name,
#                 reason=f"Digitally signed on {doctype}",
#                 location=digi.sign_address or "India",
#                 md_algorithm='sha256',
#                 certify=True,  # enables DocMDP
#                 docmdp_permissions=fields.MDPPerm.NO_CHANGES  # <— updated enum + param
#             )
#             # TSA for long-term validity
#             tsa_url = "http://timestamp.digicert.com"  # or tsa2.emudhra.com
#             timestamper = HTTPTimeStamper(tsa_url)

#             pdf_signer = signers.PdfSigner(
#                 signature_meta,
#                 signer=signer,
#                 stamp_style=QRStampStyle(
#                     stamp_text="For: %(signer)s\nTime: %(ts)s"
#                 ),
#                 timestamper=timestamper
#             )

#             pdf_signer.sign_pdf(
#                 writer,
#                 output=output,
#                 appearance_text_params={'url': digi.url}
#             )

#             signed_pdf_io = output  # carry forward for next page (if any)

#         # Attach the signed PDF
#         file_doc = frappe.get_doc({
#             "doctype": "File",
#             "file_name": f"{sales_invoice.name}-signed.pdf",
#             "is_private": 1,
#             "content": signed_pdf_io.getvalue(),
#         })
#         file_doc.insert(ignore_permissions=True)
#         # --- Validate and log results (pyHanko current API) ---
#         try:
#             pdf_bytes = signed_pdf_io.getvalue()
#             r = PdfFileReader(BytesIO(pdf_bytes))
#             embedded = list(r.embedded_signatures)  # newest last
#             vc = ValidationContext(allow_fetching=True)  # no explicit trust roots -> integrity & timestamp checks still useful

#             summary = {
#                 "file": file_doc.file_name,
#                 "url": file_doc.file_url,
#                 "signature_count": len(embedded),
#                 "signatures": []
#             }

#             for sig in embedded:
#                 status = validate_pdf_signature(sig, vc)
#                 item = {
#                     "ok": bool(getattr(status, "bottom_line", False)),
#                     "modification_level": str(getattr(status, "modification_level", None)),
#                     "docmdp_ok": bool(getattr(status, "docmdp_ok", None)),
#                     "docmdp_permissions": str(getattr(status, "docmdp_permissions", None)),
#                     "claimed_signing_time": (
#                         getattr(status, "signing_time", None).isoformat()
#                         if getattr(status, "signing_time", None) else None
#                     ),
#                     "signer_subject": None,
#                     "timestamp": {"present": False, "valid": False, "tsa_time": None},
#                     "trust_chain_ok": getattr(status, "trust_established", None),
#                 }
#                 try:
#                     item["signer_subject"] = status.signer_report.signer_cert.subject.human_friendly
#                 except Exception:
#                     pass

#                 ts = getattr(status, "timestamp_validity", None)
#                 if ts is not None:
#                     item["timestamp"] = {
#                         "present": True,
#                         "valid": bool(getattr(ts, "valid", False)),
#                         "tsa_time": (getattr(ts, "signing_time", None).isoformat()
#                                      if getattr(ts, "signing_time", None) else None),
#                     }

#                 summary["signatures"].append(item)

#             # Always log the validation summary (you can gate this on failures if you want)
#             frappe.log_error(json.dumps(summary, indent=2, default=str),
#                              f"{doctype} Digital Sign Validation • {sales_invoice.name}")

#         except Exception:
#             # Don't block the response if validation/logging has issues
#             frappe.log_error(frappe.get_traceback(),
#                              f"{doctype} Digital Sign Validation Error • {sales_invoice.name}")

#         return f"{frappe.utils.get_url(file_doc.file_url)}"
#     except ValidationError:
#         raise
#     except Exception:
#         frappe.log_error(frappe.get_traceback(), f"{doctype} Digital Sign Error")
#         frappe.msgprint("Error log created.")
#         frappe.throw("You entered an incorrect password in Document Sign Setting, or the PFX file is invalid. Please check the error log for more details.")

@frappe.whitelist()
def sign_sales_invoice_pdf(doctype, sales_invoice_name, print_format_name=None, entered_password=None, multiple_page=None, page_range=None):
    from cryptography.hazmat.primitives.serialization import pkcs12, Encoding
    from asn1crypto import x509 as asn1_x509
    import json, os, ast
    from io import BytesIO
    from frappe import ValidationError
    from pypdf import PdfReader
    from pyhanko.sign import signers, fields
    from pyhanko.sign.fields import SigFieldSpec, append_signature_field
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.stamp import QRStampStyle
    from pyhanko.sign.timestamps import HTTPTimeStamper
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext

    try:
        sales_invoice = frappe.get_doc(doctype, sales_invoice_name)
        pdf_content = frappe.get_print(
            doctype,
            sales_invoice_name,
            print_format=print_format_name or "Digital Sign",
            as_pdf=True
        )

        digi = frappe.get_doc("Document Sign Setting")
        actual_password = digi.get_password('dsc_password')
        inter_asn1 = []
        root_certs = []
        # --- Load signer from PFX and also extract intermediates ---
        if digi.pfx_file_use:
            pfx = digi.pfx_file
            if not pfx:
                frappe.throw("PFX not uploaded in Document Sign Setting.")
            pfx_file_path = frappe.get_site_path(digi.pfx_file.lstrip("/"))
            if not os.path.exists(pfx_file_path):
                frappe.throw(f"PFX file not found: {pfx_file_path}")

            try:
                with open(pfx_file_path, "rb") as f:
                    pfx_bytes = f.read()
                # Parse PFX fully to get signer cert + intermediates
                signer_key, signer_cert, extra_certs = pkcs12.load_key_and_certificates(
                    pfx_bytes, actual_password.encode()
                )

                # Convert intermediates into asn1crypto for pyHanko
                
                for c in (extra_certs or []):
                    asn1_cert = asn1_x509.Certificate.load(c.public_bytes(Encoding.DER))
                    if asn1_cert.subject == asn1_cert.issuer:  # self-signed → Root
                        root_certs.append(asn1_cert)
                    else:
                        inter_asn1.append(asn1_cert)
                frappe.log_error(f"Loaded {len(inter_asn1)} intermediate certs & {len(root_certs)} Root cert from PFX", "PFX Intermediates Info")
                signer = signers.SimpleSigner.load_pkcs12(
                    pfx_file_path,
                    passphrase=actual_password.encode(),
                    other_certs=inter_asn1 if inter_asn1 else None  # <--- embed intermeds here
                )
            except Exception:
                frappe.throw("Incorrect password or invalid PFX file.")
        else:
            frappe.throw("Only PFX flow is supported in this setup.")

        # Read and count pages
        input_pdf = BytesIO(pdf_content)
        reader = PdfReader(input_pdf)
        num_pages = len(reader.pages)
        input_pdf.seek(0)

        def parse_page_range(page_range_str, total_pages):
            result = set()
            if not page_range_str:
                return []
            parts = page_range_str.split(',')
            for part in parts:
                if '-' in part:
                    start, end = part.split('-')
                    start, end = int(start.strip()) - 1, int(end.strip()) - 1
                    result.update(range(start, end + 1))
                else:
                    result.add(int(part.strip()) - 1)
            return sorted(p for p in result if 0 <= p < total_pages)

        signed_pdf_io = input_pdf

        if int(multiple_page or 0) == 1:
            pages_to_sign = list(range(num_pages))
        elif page_range:
            pages_to_sign = parse_page_range(page_range, num_pages)
        else:
            pages_to_sign = [num_pages - 1]

        for i, page_num in enumerate(pages_to_sign):
            signed_pdf_io.seek(0)
            writer = IncrementalPdfFileWriter(signed_pdf_io)
            output = BytesIO()

            box = ast.literal_eval(digi.location) if digi.location else (345, 50, 545, 100)
            sig_field_spec = SigFieldSpec(
                sig_field_name=f"Signature_Page_{page_num + 1}",
                box=box,
                on_page=page_num
            )
            append_signature_field(writer, sig_field_spec)

            signature_meta = signers.PdfSignatureMetadata(
                field_name=sig_field_spec.sig_field_name,
                reason=f"Digitally signed on {doctype}",
                location=digi.sign_address or "India",
                md_algorithm='sha256',
                # certify=True,
                docmdp_permissions=fields.MDPPerm.NO_CHANGES
            )
            tsa_url = "http://timestamp.digicert.com"  # replace with valid TSA if provided
            timestamper = HTTPTimeStamper(tsa_url)
            signer_display = digi.get("sign_address") or getattr(sales_invoice, "company", "Signer")
            stamp_text = f"Digitally Signed by\n{signer_display}\nTime: %(ts)s"
            pdf_signer = signers.PdfSigner(
                signature_meta,
                signer=signer,
                stamp_style=QRStampStyle(stamp_text=stamp_text),
                timestamper=timestamper
            )

            pdf_signer.sign_pdf(
                writer,
                output=output,
                appearance_text_params={'url': digi.url}
            )

            signed_pdf_io = output

        # Attach the signed PDF
        file_doc = frappe.get_doc({
            "doctype": "File",
            "file_name": f"{sales_invoice.name}-signed.pdf",
            "is_private": 1,
            "content": signed_pdf_io.getvalue(),
        })
        file_doc.insert(ignore_permissions=True)

        # --- Validate and log results ---
        try:
            pdf_bytes = signed_pdf_io.getvalue()
            r = PdfFileReader(BytesIO(pdf_bytes))
            embedded = list(r.embedded_signatures)

            # # Build VC: trust_roots from settings
            # roots = []
            # from asn1crypto import pem
            # roots_pem = getattr(digi, "trusted_roots_pem", "") or ""
            # if roots_pem.strip():
            #     rest = roots_pem.encode()
            #     while True:
            #         try:
            #             _t, _h, der = pem.unarmor(rest, multiple=True)
            #             roots.append(asn1_x509.Certificate.load(der))
            #             if not der:
            #                 break
            #             rest = der
            #         except Exception:
            #             break

            vc = ValidationContext(
                trust_roots=root_certs,
                other_certs=inter_asn1,
                allow_fetching=True
            )

            summary = {
                "file": file_doc.file_name,
                "url": file_doc.file_url,
                "signature_count": len(embedded),
                "signatures": []
            }

            for sig in embedded:
                status = validate_pdf_signature(sig, vc)
                item = {
                    "ok": bool(getattr(status, "bottom_line", False)),
                    "modification_level": str(getattr(status, "modification_level", None)),
                    "docmdp_ok": bool(getattr(status, "docmdp_ok", None)),
                    "docmdp_permissions": str(getattr(status, "docmdp_permissions", None)),
                    "claimed_signing_time": (
                        getattr(status, "signing_time", None).isoformat()
                        if getattr(status, "signing_time", None) else None
                    ),
                    "signer_subject": None,
                    "timestamp": {"present": False, "valid": False, "tsa_time": None},
                    "trust_chain_ok": getattr(status, "trust_established", None),
                }
                try:
                    item["signer_subject"] = status.signer_report.signer_cert.subject.human_friendly
                except Exception:
                    pass

                ts = getattr(status, "timestamp_validity", None)
                if ts is not None:
                    item["timestamp"] = {
                        "present": True,
                        "valid": bool(getattr(ts, "valid", False)),
                        "tsa_time": (getattr(ts, "signing_time", None).isoformat()
                                     if getattr(ts, "signing_time", None) else None),
                    }

                summary["signatures"].append(item)

            frappe.log_error(json.dumps(summary, indent=2, default=str),
                             f"{doctype} Digital Sign Validation • {sales_invoice.name}")

        except Exception:
            frappe.log_error(frappe.get_traceback(),
                             f"{doctype} Digital Sign Validation Error • {sales_invoice.name}")

        return f"{frappe.utils.get_url(file_doc.file_url)}"

    except ValidationError:
        raise
    except Exception:
        frappe.log_error(frappe.get_traceback(), f"{doctype} Digital Sign Error")
        frappe.msgprint("Error log created.")
        frappe.throw("You entered an incorrect password in Document Sign Setting, or the PFX file is invalid. Please check the error log.")


@frappe.whitelist()
def get_pdf_base64(doctype,name,print_format_name):
    pdf_content = frappe.get_print(doctype, name, print_format = print_format_name or "Digital Sign", as_pdf=True)
    return base64.b64encode(pdf_content).decode('utf-8')

@frappe.whitelist()
def save_signed_pdf(doctype,docname, signed_pdf_base64):
    file_path = f"/tmp/{docname}-signed.pdf"
    with open(file_path, "wb") as f:
        f.write(base64.b64decode(signed_pdf_base64))

    with open(file_path, "rb") as signed_file:
        file_doc = frappe.get_doc({
            "doctype": "File",
            "file_name": f"{docname}-signed.pdf",
            "is_private": 1,
            "content": signed_file.read(),
        })
        file_doc.insert(ignore_permissions=True)
