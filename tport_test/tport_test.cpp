#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>

#define MSG_PUB_T struct sip_s
#include <sofia-sip/msg.h>
#include <sofia-sip/nta.h>
#include <sofia-sip/sip_header.h>
#include <sofia-sip/su_log.h>

using namespace std;

enum class ProcState : std::uint8_t {Starting, Running, Aborting};

static su_root_t* root = nullptr;
// static ProcState state = ProcState::Starting;
//
// static void sigterm_handler(int) noexcept {
// 	switch (state) {
// 		case ProcState::Starting:
// 			state = ProcState::Aborting;
// 			break;
// 		case ProcState::Running:
// 			su_root_break(root);
// 			break;
// 		case ProcState::Aborting:
// 			break;
// 	}
// }

static int on_message_response(nta_outgoing_magic_t *magic, nta_outgoing_t *request, sip_t const *sip) noexcept {
	const auto& statusCode = sip->sip_status->st_status;
	const auto& phrase = sip->sip_status->st_phrase;
	cout << "\nReceiving response: " << statusCode << " " << phrase << "\n" << endl;

	if (root) su_root_break(root);

	return 0;
}

int main() {
// 	signal(SIGTERM, sigterm_handler);
// 	signal(SIGINT, sigterm_handler);

	su_log_set_level(nullptr, SU_LOG_MAX);

	root = su_root_create(nullptr);

	url_string_t url{};
	strncpy(url.us_str, "sips:127.0.0.1", URL_MAXLEN);

	auto* agent = nta_agent_create(root, &url, nullptr, nullptr, TAG_END());

	auto* msg = nta_msg_create(agent, 0);
	auto* sip_message = msg_object(msg);

	auto* home = su_home_create();

	url_string_t request_uri{};
	strncpy(request_uri.us_str, "sip:127.0.0.1:5062;transport=tls", URL_MAXLEN);
	auto* request_line = sip_request_create(home, sip_method_message, nullptr, &request_uri, nullptr);
	msg_header_add_dup(msg, sip_message, reinterpret_cast<msg_header_t*>(request_line));

	url_string_t from_uri{};
	strncpy(from_uri.us_str, "sips:127.0.0.1", URL_MAXLEN);
	auto* from = sip_from_create(home, &from_uri);
	msg_header_add_dup(msg, sip_message, reinterpret_cast<msg_header_t*>(from));

	url_string_t to_uri{};
	strncpy(to_uri.us_str, "sips:127.0.0.1:5062", URL_MAXLEN);
	auto* to = sip_to_create(home, &to_uri);
	msg_header_add_dup(msg, sip_message, reinterpret_cast<msg_header_t*>(to));

	auto* callid = sip_call_id_create(home, nullptr);
	msg_header_add_dup(msg, sip_message, reinterpret_cast<msg_header_t*>(callid));

	auto* cseq = sip_cseq_create(home, 20, sip_method_message, nullptr);
	msg_header_add_dup(msg, sip_message, reinterpret_cast<msg_header_t*>(cseq));

	auto* sep = sip_separator_create(home);
	msg_header_add_dup(msg, sip_message, reinterpret_cast<msg_header_t*>(sep));

	su_home_unref(home);



	auto* out_transaction = nta_outgoing_mcreate(agent, on_message_response, nullptr, nullptr, msg, TAG_END());

	su_root_run(root);

	// Cleaning
	nta_agent_destroy(agent);
	su_root_destroy(root);
	return 0;
}
