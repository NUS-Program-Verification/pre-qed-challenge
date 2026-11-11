/* SPIRV-Tools public C API (include/spirv-tools/libspirv.h): all 71 declarations,
 * and the C++ API of libspirv.hpp, optimizer.hpp, linker.hpp and linter.hpp that
 * the C API does not reach by itself (second half of the file).
 * Data flow: assembly text -> spvTextToBinary(WithOptions) -> spv_binary; the
 * words of that binary, of the optimizer output, or of the record payload feed
 * spvBinaryToText, spvValidate*, spvBinaryParse and spvOptimizerRun; the text
 * produced by spvBinaryToText feeds back into the assembler.
 */
#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "spirv-tools/libspirv.h"
#include "spirv-tools/libspirv.hpp"
#include "spirv-tools/linker.hpp"
#include "spirv-tools/linter.hpp"
#include "spirv-tools/optimizer.hpp"
#include "preqed_ltl.h"

typedef struct {
  const uint8_t* p;
  size_t n;
} payload;

/* Caps that keep a single record short: the validator/disassembler are linear
 * in the word count, the optimizer pass pipelines are not. A Register*Passes
 * bundle counts 8 against kMaxPassBudget. */
enum { kMaxWords = 8192, kMaxOptWords = 1024, kMaxPassBudget = 32, kMaxFlags = 8 };

static spv_context context;
static spv_target_env env = SPV_ENV_UNIVERSAL_1_0;
static spv_validator_options validator_options;
static spv_optimizer_options optimizer_options;
static spv_reducer_options reducer_options;
static spv_fuzzer_options fuzzer_options;
static spv_optimizer_t* optimizer;
static spv_binary binary;       /* spvTextToBinary(WithOptions) output */
static spv_binary optimized;    /* spvOptimizerRun output, freed by spvBinaryDestroy */
static spv_text disassembly;    /* spvBinaryToText output */
static spv_diagnostic diagnostic;
static std::vector<uint32_t> raw;
static std::string last_text;   /* copy of the last disassembly, fed to the assembler */
static unsigned pass_budget;
static int optimizer_skips_validation;  /* spvOptimizerOptionsSetRunValidator(false) */
/* A run failed: opt/pass_manager.cpp:77 resets every pass that ran to nullptr and
 * clears the list only after a fully successful run, so the next run dereferences a
 * null pass (pass_manager.cpp:58, repro2.cpp case 3). The optimizer is destroyed first. */
static int optimizer_failed;
static unsigned consumer_messages;
static uint32_t parsed_words;

static uint8_t byte(payload in, size_t i) { return i < in.n ? in.p[i] : 0; }
static payload rest(payload in, size_t skip) {
  payload r = { in.p + (skip < in.n ? skip : in.n), in.n > skip ? in.n - skip : 0 };
  return r;
}
static uint32_t word(payload in, size_t i) {
  return uint32_t(byte(in, 4 * i)) | uint32_t(byte(in, 4 * i + 1)) << 8 |
         uint32_t(byte(in, 4 * i + 2)) << 16 | uint32_t(byte(in, 4 * i + 3)) << 24;
}
static std::string text_of(payload in) {
  return std::string(reinterpret_cast<const char*>(in.p), in.n);
}

/* spirv_target_env.cpp:67 and opt/optimizer.cpp:78 assert on the deprecated
 * SPV_ENV_WEBGPU_0 value, so every environment selection skips it. */
static spv_target_env env_of(uint8_t b) {
  spv_target_env e = static_cast<spv_target_env>(b % SPV_ENV_MAX);
  return e == SPV_ENV_WEBGPU_0 ? SPV_ENV_UNIVERSAL_1_0 : e;
}

/* diagnostic.cpp:120 asserts *diagnostic == nullptr and text.cpp:995 overwrites
 * the slot, so a diagnostic out-parameter is only passed when it is empty. */
static spv_diagnostic* diag_slot(void) { return diagnostic ? nullptr : &diagnostic; }

/* Picks the words for a binary consumer: 0 = assembler output, 1 = optimizer
 * output, 2 (or an absent object) = the record payload copied into words. */
static const uint32_t* words_for(uint8_t sel, size_t cap, size_t* count, payload in) {
  const uint32_t* w = nullptr;
  size_t n = 0;
  if (sel % 3 == 0 && binary && binary->wordCount) {
    w = binary->code;
    n = binary->wordCount;
  } else if (sel % 3 == 1 && optimized && optimized->wordCount) {
    w = optimized->code;
    n = optimized->wordCount;
  }
  if (!w) {
    n = in.n / 4;
    raw.assign(n, 0);
    for (size_t i = 0; i < n; i++) raw[i] = word(in, i);
    w = raw.data();
  }
  if (n > cap) n = cap;
  *count = n;
  return n ? w : nullptr;
}

/* The assembler input: the record bytes, or the last disassembly. */
static std::string text_pick(payload in) {
  if ((byte(in, 0) & 1) && !last_text.empty()) return last_text;
  return text_of(rest(in, 1));
}

static spv_const_binary_t as_const_binary(const uint32_t* w, size_t n) {
  spv_const_binary_t b = { w, n };
  return b;
}

static spv_result_t parse_header(void*, spv_endianness_t, uint32_t, uint32_t,
                                 uint32_t, uint32_t, uint32_t) {
  return SPV_SUCCESS;
}
static spv_result_t parse_instruction(void*, const spv_parsed_instruction_t* inst) {
  parsed_words += inst->num_words;
  return SPV_SUCCESS;
}

/* optimizer.cpp:1243 calls the consumer unconditionally, so it is never null. */
static void quiet_consumer(spv_message_level_t, const char*, const spv_position_t*,
                           const char*) {
  consumer_messages++;
}

/* version, operand helpers, target environments */

static void call_spvSoftwareVersionString(payload in) {
  (void)in;
  if (!preqed_call("spvSoftwareVersionString")) return;
  const char* s = spvSoftwareVersionString();
  preqed_result("spvSoftwareVersionString", s && *s);
}
static void call_spvSoftwareVersionDetailsString(payload in) {
  (void)in;
  if (!preqed_call("spvSoftwareVersionDetailsString")) return;
  const char* s = spvSoftwareVersionDetailsString();
  preqed_result("spvSoftwareVersionDetailsString", s && *s);
}
static void call_spvOperandIsConcrete(payload in) {
  if (!preqed_call("spvOperandIsConcrete")) return;
  spvOperandIsConcrete(static_cast<spv_operand_type_t>(
      byte(in, 0) % SPV_OPERAND_TYPE_NUM_OPERAND_TYPES));
  preqed_result("spvOperandIsConcrete", 1);
}
static void call_spvOperandIsConcreteMask(payload in) {
  if (!preqed_call("spvOperandIsConcreteMask")) return;
  spvOperandIsConcreteMask(static_cast<spv_operand_type_t>(
      byte(in, 0) % SPV_OPERAND_TYPE_NUM_OPERAND_TYPES));
  preqed_result("spvOperandIsConcreteMask", 1);
}
static void call_spvTargetEnvDescription(payload in) {
  if (!preqed_call("spvTargetEnvDescription")) return;
  const char* s = spvTargetEnvDescription(env_of(byte(in, 0)));
  preqed_result("spvTargetEnvDescription", s && *s);
}
static void call_spvParseTargetEnv(payload in) {
  std::string name = text_of(in);
  spv_target_env parsed = env;
  if (!preqed_call("spvParseTargetEnv")) return;
  bool ok = spvParseTargetEnv(name.c_str(), &parsed);
  preqed_result("spvParseTargetEnv", ok);
  if (ok) env = env_of(static_cast<uint8_t>(parsed));
}
static void call_spvParseVulkanEnv(payload in) {
  spv_target_env parsed = env;
  if (!preqed_call("spvParseVulkanEnv")) return;
  bool ok = spvParseVulkanEnv(word(in, 0), word(in, 1), &parsed);
  preqed_result("spvParseVulkanEnv", ok);
  if (ok) env = env_of(static_cast<uint8_t>(parsed));
}

/* context */
/* ltl: context_lifecycle */
static void call_spvContextCreate(payload in) {
  if (context) return;
  if (!preqed_call("spvContextCreate")) return;
  context = spvContextCreate(env_of(byte(in, 0)));
  preqed_result("spvContextCreate", context != nullptr);
}
/* ltl: context_lifecycle */
static void call_spvContextDestroy(payload in) {
  (void)in;
  if (!context) return;
  if (!preqed_call("spvContextDestroy")) return;
  spvContextDestroy(context);
  context = nullptr;
  preqed_result("spvContextDestroy", 1);
}

/* validator options */
/* ltl: validator_options_lifecycle */
static void call_spvValidatorOptionsCreate(payload in) {
  (void)in;
  if (validator_options) return;
  if (!preqed_call("spvValidatorOptionsCreate")) return;
  validator_options = spvValidatorOptionsCreate();
  preqed_result("spvValidatorOptionsCreate", validator_options != nullptr);
}
/* ltl: validator_options_lifecycle */
static void call_spvValidatorOptionsDestroy(payload in) {
  (void)in;
  if (!validator_options) return;
  if (!preqed_call("spvValidatorOptionsDestroy")) return;
  spvValidatorOptionsDestroy(validator_options);
  validator_options = nullptr;
  preqed_result("spvValidatorOptionsDestroy", 1);
}
/* ltl: validator_options_lifecycle */
static void call_spvValidatorOptionsSetUniversalLimit(payload in) {
  if (!validator_options) return;
  if (!preqed_call("spvValidatorOptionsSetUniversalLimit")) return;
  spv_validator_limit limit =
      static_cast<spv_validator_limit>(byte(in, 0) % 9);  /* the 9 spv_validator_limit values */
  spvValidatorOptionsSetUniversalLimit(validator_options, limit, word(in, 1) | 1u);  /* any non-zero limit */
  preqed_result("spvValidatorOptionsSetUniversalLimit", 1);
}

#define VALIDATOR_BOOL(NAME)                                        \
  static void call_##NAME(payload in) {                             \
    if (!validator_options) return;                                 \
    if (!preqed_call(#NAME)) return;                               \
    NAME(validator_options, (byte(in, 0) & 1) != 0);                \
    preqed_result(#NAME, 1);                                       \
  }
/* ltl: validator_options_lifecycle */
VALIDATOR_BOOL(spvValidatorOptionsSetRelaxStoreStruct)
/* ltl: validator_options_lifecycle */
VALIDATOR_BOOL(spvValidatorOptionsSetRelaxLogicalPointer)
/* ltl: validator_options_lifecycle */
VALIDATOR_BOOL(spvValidatorOptionsSetBeforeHlslLegalization)
/* ltl: validator_options_lifecycle */
VALIDATOR_BOOL(spvValidatorOptionsSetRelaxBlockLayout)
/* ltl: validator_options_lifecycle */
VALIDATOR_BOOL(spvValidatorOptionsSetUniformBufferStandardLayout)
/* ltl: validator_options_lifecycle */
VALIDATOR_BOOL(spvValidatorOptionsSetScalarBlockLayout)
/* ltl: validator_options_lifecycle */
VALIDATOR_BOOL(spvValidatorOptionsSetWorkgroupScalarBlockLayout)
/* ltl: validator_options_lifecycle */
VALIDATOR_BOOL(spvValidatorOptionsSetSkipBlockLayout)
/* ltl: validator_options_lifecycle */
VALIDATOR_BOOL(spvValidatorOptionsSetAllowLocalSizeId)
/* ltl: validator_options_lifecycle */
VALIDATOR_BOOL(spvValidatorOptionsSetAllowOffsetTextureOperand)
/* ltl: validator_options_lifecycle */
VALIDATOR_BOOL(spvValidatorOptionsSetAllowVulkan32BitBitwise)
/* ltl: validator_options_lifecycle */
VALIDATOR_BOOL(spvValidatorOptionsSetFriendlyNames)
#undef VALIDATOR_BOOL

#define VALIDATOR_LAYOUT(NAME)                                      \
  static void call_##NAME(payload in) {                             \
    if (!validator_options) return;                                 \
    if (!preqed_call(#NAME)) return;                               \
    NAME(validator_options, 1u + word(in, 0) % 4096u, 1u << (byte(in, 0) % 6));  /* size 1..4096, alignment 1..32 */ \
    preqed_result(#NAME, 1);                                       \
  }
/* ltl: validator_options_lifecycle */
VALIDATOR_LAYOUT(spvValidatorOptionsSetBufferDescriptorLayout)
/* ltl: validator_options_lifecycle */
VALIDATOR_LAYOUT(spvValidatorOptionsSetImageDescriptorLayout)
/* ltl: validator_options_lifecycle */
VALIDATOR_LAYOUT(spvValidatorOptionsSetSamplerDescriptorLayout)
/* ltl: validator_options_lifecycle */
VALIDATOR_LAYOUT(spvValidatorOptionsSetTensorDescriptorLayout)
#undef VALIDATOR_LAYOUT

/* optimizer options */
/* ltl: optimizer_options_lifecycle */
static void call_spvOptimizerOptionsCreate(payload in) {
  (void)in;
  if (optimizer_options) return;
  if (!preqed_call("spvOptimizerOptionsCreate")) return;
  optimizer_options = spvOptimizerOptionsCreate();
  optimizer_skips_validation = 0;
  preqed_result("spvOptimizerOptionsCreate", optimizer_options != nullptr);
}
/* ltl: optimizer_options_lifecycle */
static void call_spvOptimizerOptionsDestroy(payload in) {
  (void)in;
  if (!optimizer_options) return;
  if (!preqed_call("spvOptimizerOptionsDestroy")) return;
  spvOptimizerOptionsDestroy(optimizer_options);
  optimizer_options = nullptr;
  optimizer_skips_validation = 0;
  preqed_result("spvOptimizerOptionsDestroy", 1);
}
/* ltl: optimizer_options_lifecycle */
static void call_spvOptimizerOptionsSetRunValidator(payload in) {
  if (!optimizer_options) return;
  if (!preqed_call("spvOptimizerOptionsSetRunValidator")) return;
  int run_validator = (byte(in, 0) & 1) != 0;
  spvOptimizerOptionsSetRunValidator(optimizer_options, run_validator);
  optimizer_skips_validation = !run_validator;
  preqed_result("spvOptimizerOptionsSetRunValidator", 1);
}
/* ltl: validator_options_lifecycle, optimizer_options_lifecycle */
static void call_spvOptimizerOptionsSetValidatorOptions(payload in) {
  (void)in;
  if (!optimizer_options || !validator_options) return;
  if (!preqed_call("spvOptimizerOptionsSetValidatorOptions")) return;
  spvOptimizerOptionsSetValidatorOptions(optimizer_options, validator_options);
  preqed_result("spvOptimizerOptionsSetValidatorOptions", 1);
}
/* ltl: optimizer_options_lifecycle */
static void call_spvOptimizerOptionsSetMaxIdBound(payload in) {
  if (!optimizer_options) return;
  if (!preqed_call("spvOptimizerOptionsSetMaxIdBound")) return;
  spvOptimizerOptionsSetMaxIdBound(optimizer_options, word(in, 0) | 1u);
  preqed_result("spvOptimizerOptionsSetMaxIdBound", 1);
}
/* ltl: optimizer_options_lifecycle */
static void call_spvOptimizerOptionsSetPreserveBindings(payload in) {
  if (!optimizer_options) return;
  if (!preqed_call("spvOptimizerOptionsSetPreserveBindings")) return;
  spvOptimizerOptionsSetPreserveBindings(optimizer_options, (byte(in, 0) & 1) != 0);
  preqed_result("spvOptimizerOptionsSetPreserveBindings", 1);
}
/* ltl: optimizer_options_lifecycle */
static void call_spvOptimizerOptionsSetPreserveSpecConstants(payload in) {
  if (!optimizer_options) return;
  if (!preqed_call("spvOptimizerOptionsSetPreserveSpecConstants")) return;
  spvOptimizerOptionsSetPreserveSpecConstants(optimizer_options,
                                              (byte(in, 0) & 1) != 0);
  preqed_result("spvOptimizerOptionsSetPreserveSpecConstants", 1);
}

/* reducer options */
/* ltl: reducer_options_lifecycle */
static void call_spvReducerOptionsCreate(payload in) {
  (void)in;
  if (reducer_options) return;
  if (!preqed_call("spvReducerOptionsCreate")) return;
  reducer_options = spvReducerOptionsCreate();
  preqed_result("spvReducerOptionsCreate", reducer_options != nullptr);
}
/* ltl: reducer_options_lifecycle */
static void call_spvReducerOptionsDestroy(payload in) {
  (void)in;
  if (!reducer_options) return;
  if (!preqed_call("spvReducerOptionsDestroy")) return;
  spvReducerOptionsDestroy(reducer_options);
  reducer_options = nullptr;
  preqed_result("spvReducerOptionsDestroy", 1);
}
/* ltl: reducer_options_lifecycle */
static void call_spvReducerOptionsSetStepLimit(payload in) {
  if (!reducer_options) return;
  if (!preqed_call("spvReducerOptionsSetStepLimit")) return;
  spvReducerOptionsSetStepLimit(reducer_options, word(in, 0) % 5000u);
  preqed_result("spvReducerOptionsSetStepLimit", 1);
}
/* ltl: reducer_options_lifecycle */
static void call_spvReducerOptionsSetFailOnValidationError(payload in) {
  if (!reducer_options) return;
  if (!preqed_call("spvReducerOptionsSetFailOnValidationError")) return;
  spvReducerOptionsSetFailOnValidationError(reducer_options, (byte(in, 0) & 1) != 0);
  preqed_result("spvReducerOptionsSetFailOnValidationError", 1);
}
/* ltl: reducer_options_lifecycle */
static void call_spvReducerOptionsSetTargetFunction(payload in) {
  if (!reducer_options) return;
  if (!preqed_call("spvReducerOptionsSetTargetFunction")) return;
  spvReducerOptionsSetTargetFunction(reducer_options, word(in, 0));
  preqed_result("spvReducerOptionsSetTargetFunction", 1);
}

/* fuzzer options */
/* ltl: fuzzer_options_lifecycle */
static void call_spvFuzzerOptionsCreate(payload in) {
  (void)in;
  if (fuzzer_options) return;
  if (!preqed_call("spvFuzzerOptionsCreate")) return;
  fuzzer_options = spvFuzzerOptionsCreate();
  preqed_result("spvFuzzerOptionsCreate", fuzzer_options != nullptr);
}
/* ltl: fuzzer_options_lifecycle */
static void call_spvFuzzerOptionsDestroy(payload in) {
  (void)in;
  if (!fuzzer_options) return;
  if (!preqed_call("spvFuzzerOptionsDestroy")) return;
  spvFuzzerOptionsDestroy(fuzzer_options);
  fuzzer_options = nullptr;
  preqed_result("spvFuzzerOptionsDestroy", 1);
}
/* ltl: fuzzer_options_lifecycle */
static void call_spvFuzzerOptionsEnableReplayValidation(payload in) {
  (void)in;
  if (!fuzzer_options) return;
  if (!preqed_call("spvFuzzerOptionsEnableReplayValidation")) return;
  spvFuzzerOptionsEnableReplayValidation(fuzzer_options);
  preqed_result("spvFuzzerOptionsEnableReplayValidation", 1);
}
/* ltl: fuzzer_options_lifecycle */
static void call_spvFuzzerOptionsSetRandomSeed(payload in) {
  if (!fuzzer_options) return;
  if (!preqed_call("spvFuzzerOptionsSetRandomSeed")) return;
  spvFuzzerOptionsSetRandomSeed(fuzzer_options, word(in, 0));
  preqed_result("spvFuzzerOptionsSetRandomSeed", 1);
}
/* ltl: fuzzer_options_lifecycle */
static void call_spvFuzzerOptionsSetReplayRange(payload in) {
  if (!fuzzer_options) return;
  if (!preqed_call("spvFuzzerOptionsSetReplayRange")) return;
  spvFuzzerOptionsSetReplayRange(fuzzer_options,
                                 static_cast<int32_t>(word(in, 0) % 201u) - 100);  /* -100..100; negative counts from the end */
  preqed_result("spvFuzzerOptionsSetReplayRange", 1);
}
/* ltl: fuzzer_options_lifecycle */
static void call_spvFuzzerOptionsSetShrinkerStepLimit(payload in) {
  if (!fuzzer_options) return;
  if (!preqed_call("spvFuzzerOptionsSetShrinkerStepLimit")) return;
  spvFuzzerOptionsSetShrinkerStepLimit(fuzzer_options, word(in, 0) % 5000u);
  preqed_result("spvFuzzerOptionsSetShrinkerStepLimit", 1);
}
/* ltl: fuzzer_options_lifecycle */
static void call_spvFuzzerOptionsEnableFuzzerPassValidation(payload in) {
  (void)in;
  if (!fuzzer_options) return;
  if (!preqed_call("spvFuzzerOptionsEnableFuzzerPassValidation")) return;
  spvFuzzerOptionsEnableFuzzerPassValidation(fuzzer_options);
  preqed_result("spvFuzzerOptionsEnableFuzzerPassValidation", 1);
}
/* ltl: fuzzer_options_lifecycle */
static void call_spvFuzzerOptionsEnableAllPasses(payload in) {
  (void)in;
  if (!fuzzer_options) return;
  if (!preqed_call("spvFuzzerOptionsEnableAllPasses")) return;
  spvFuzzerOptionsEnableAllPasses(fuzzer_options);
  preqed_result("spvFuzzerOptionsEnableAllPasses", 1);
}

/* assembler and disassembler */
/* ltl: context_lifecycle, binary_ownership, diagnostic_ownership */
static void call_spvTextToBinary(payload in) {
  if (!context || binary) return;
  std::string source = text_pick(in);
  spv_binary out = nullptr;
  if (!preqed_call("spvTextToBinary")) return;
  spv_result_t result =
      spvTextToBinary(context, source.data(), source.size(), &out, diag_slot());
  preqed_result("spvTextToBinary", result == SPV_SUCCESS);
  if (result == SPV_SUCCESS) binary = out;
}
/* ltl: context_lifecycle, binary_ownership, diagnostic_ownership */
static void call_spvTextToBinaryWithOptions(payload in) {
  if (!context || binary) return;
  std::string source = text_pick(in);
  uint32_t options = byte(in, 0) & 2 ? SPV_TEXT_TO_BINARY_OPTION_PRESERVE_NUMERIC_IDS
                                     : SPV_TEXT_TO_BINARY_OPTION_NONE;
  spv_binary out = nullptr;
  if (!preqed_call("spvTextToBinaryWithOptions")) return;
  spv_result_t result = spvTextToBinaryWithOptions(
      context, source.data(), source.size(), options, &out, diag_slot());
  preqed_result("spvTextToBinaryWithOptions", result == SPV_SUCCESS);
  if (result == SPV_SUCCESS) binary = out;
}
/* ltl: text_ownership */
static void call_spvTextDestroy(payload in) {
  (void)in;
  if (!disassembly) return;
  if (!preqed_call("spvTextDestroy")) return;
  spvTextDestroy(disassembly);
  disassembly = nullptr;
  preqed_result("spvTextDestroy", 1);
}
/* ltl: context_lifecycle, text_ownership, diagnostic_ownership */
static void call_spvBinaryToText(payload in) {
  if (!context || disassembly) return;
  size_t count = 0;
  /* payload: selector | 4 option bytes | words when the selector asks for payload words */
  const uint32_t* words = words_for(byte(in, 0), kMaxWords, &count, rest(in, 5));
  if (!words) return;
  /* SPV_BINARY_TO_TEXT_OPTION_PRINT is left out: it writes the whole
   * disassembly to stdout, which only slows a fuzzing run down. */
  uint32_t options = word(in, 1) & (SPV_BINARY_TO_TEXT_OPTION_COLOR |
                                    SPV_BINARY_TO_TEXT_OPTION_INDENT |
                                    SPV_BINARY_TO_TEXT_OPTION_SHOW_BYTE_OFFSET |
                                    SPV_BINARY_TO_TEXT_OPTION_NO_HEADER |
                                    SPV_BINARY_TO_TEXT_OPTION_FRIENDLY_NAMES |
                                    SPV_BINARY_TO_TEXT_OPTION_COMMENT |
                                    SPV_BINARY_TO_TEXT_OPTION_NESTED_INDENT |
                                    SPV_BINARY_TO_TEXT_OPTION_REORDER_BLOCKS |
                                    SPV_BINARY_TO_TEXT_OPTION_HANDLE_UNKNOWN_OPCODES);
  spv_text out = nullptr;
  if (!preqed_call("spvBinaryToText")) return;
  spv_result_t result =
      spvBinaryToText(context, words, count, options, &out, diag_slot());
  preqed_result("spvBinaryToText", result == SPV_SUCCESS);
  if (result == SPV_SUCCESS && out) {
    disassembly = out;
    last_text.assign(out->str, out->str + out->length);
  }
}
/* ltl: binary_ownership */
static void call_spvBinaryDestroy(payload in) {
  spv_binary* slot = (byte(in, 0) & 1) ? (optimized ? &optimized : &binary)
                                       : (binary ? &binary : &optimized);
  if (!*slot) return;
  if (!preqed_call("spvBinaryDestroy")) return;
  spvBinaryDestroy(*slot);
  *slot = nullptr;
  preqed_result("spvBinaryDestroy", 1);
}

/* validator */
/* ltl: context_lifecycle, diagnostic_ownership */
static void call_spvValidate(payload in) {
  if (!context) return;
  size_t count = 0;
  const uint32_t* words = words_for(byte(in, 0), kMaxWords, &count, rest(in, 1));
  if (!words) return;
  spv_const_binary_t input = as_const_binary(words, count);
  if (!preqed_call("spvValidate")) return;
  spv_result_t result = spvValidate(context, &input, diag_slot());
  preqed_result("spvValidate", result == SPV_SUCCESS);
}
/* ltl: context_lifecycle, validator_options_lifecycle, diagnostic_ownership */
static void call_spvValidateWithOptions(payload in) {
  if (!context || !validator_options) return;
  size_t count = 0;
  const uint32_t* words = words_for(byte(in, 0), kMaxWords, &count, rest(in, 1));
  if (!words) return;
  spv_const_binary_t input = as_const_binary(words, count);
  if (!preqed_call("spvValidateWithOptions")) return;
  spv_result_t result =
      spvValidateWithOptions(context, validator_options, &input, diag_slot());
  preqed_result("spvValidateWithOptions", result == SPV_SUCCESS);
}
/* ltl: context_lifecycle, diagnostic_ownership */
static void call_spvValidateBinary(payload in) {
  if (!context) return;
  size_t count = 0;
  const uint32_t* words = words_for(byte(in, 0), kMaxWords, &count, rest(in, 1));
  if (!words) return;
  if (!preqed_call("spvValidateBinary")) return;
  spv_result_t result = spvValidateBinary(context, words, count, diag_slot());
  preqed_result("spvValidateBinary", result == SPV_SUCCESS);
}

/* diagnostics */
/* ltl: diagnostic_ownership */
static void call_spvDiagnosticCreate(payload in) {
  if (diagnostic) return;
  spv_position_t position = { byte(in, 0), byte(in, 1), word(in, 2) };
  std::string message = text_of(rest(in, 6));
  if (!preqed_call("spvDiagnosticCreate")) return;
  diagnostic = spvDiagnosticCreate(&position, message.c_str());
  preqed_result("spvDiagnosticCreate", diagnostic != nullptr);
}
/* ltl: diagnostic_ownership */
static void call_spvDiagnosticDestroy(payload in) {
  (void)in;
  if (!diagnostic) return;
  if (!preqed_call("spvDiagnosticDestroy")) return;
  spvDiagnosticDestroy(diagnostic);
  diagnostic = nullptr;
  preqed_result("spvDiagnosticDestroy", 1);
}
/* ltl: diagnostic_ownership */
static void call_spvDiagnosticPrint(payload in) {
  (void)in;
  if (!diagnostic) return;
  if (!preqed_call("spvDiagnosticPrint")) return;
  spv_result_t result = spvDiagnosticPrint(diagnostic);
  preqed_result("spvDiagnosticPrint", result == SPV_SUCCESS);
}

/* opcode table and binary parser */

static void call_spvOpcodeString(payload in) {
  (void)in;
  /* opcode.cpp:94 asserts on an unknown opcode, so only an opcode read from a
   * produced binary (word 5 is the first instruction after the 5-word header)
   * is passed. */
  const spv_binary source = binary ? binary : optimized;
  if (!source || source->wordCount <= 5) return;
  if (!preqed_call("spvOpcodeString")) return;
  const char* name = spvOpcodeString(source->code[5] & 0xffffu);
  preqed_result("spvOpcodeString", name && *name);
}
/* ltl: context_lifecycle, diagnostic_ownership */
static void call_spvBinaryParse(payload in) {
  if (!context) return;
  size_t count = 0;
  const uint32_t* words = words_for(byte(in, 0), kMaxWords, &count, rest(in, 1));
  if (!words) return;
  uint8_t kinds = byte(in, 0);
  /* bits 2/3 install the header / instruction callbacks; both may be NULL (libspirv.h) */
  spv_parsed_header_fn_t on_header = (kinds & 4) ? parse_header : nullptr;
  spv_parsed_instruction_fn_t on_instruction = (kinds & 8) ? parse_instruction : nullptr;
  if (!preqed_call("spvBinaryParse")) return;
  spv_result_t result = spvBinaryParse(context, nullptr, words, count, on_header,
                                       on_instruction, diag_slot());
  preqed_result("spvBinaryParse", result == SPV_SUCCESS);
}

/* optimizer */
/* ltl: optimizer_lifecycle */
static void call_spvOptimizerCreate(payload in) {
  if (optimizer) return;
  if (!preqed_call("spvOptimizerCreate")) return;
  optimizer = spvOptimizerCreate(env_of(byte(in, 0)));
  preqed_result("spvOptimizerCreate", optimizer != nullptr);
}
/* ltl: optimizer_lifecycle, no_run_after_failed_run */
static void call_spvOptimizerDestroy(payload in) {
  (void)in;
  if (!optimizer) return;
  if (!preqed_call("spvOptimizerDestroy")) return;
  spvOptimizerDestroy(optimizer);
  optimizer = nullptr;
  pass_budget = 0;
  optimizer_failed = 0;
  preqed_result("spvOptimizerDestroy", 1);
}
/* ltl: optimizer_lifecycle */
static void call_spvOptimizerSetMessageConsumer(payload in) {
  (void)in;
  if (!optimizer) return;
  if (!preqed_call("spvOptimizerSetMessageConsumer")) return;
  spvOptimizerSetMessageConsumer(optimizer, quiet_consumer);
  preqed_result("spvOptimizerSetMessageConsumer", 1);
}
/* ltl: optimizer_lifecycle */
static void call_spvOptimizerRegisterLegalizationPasses(payload in) {
  (void)in;
  if (!optimizer || pass_budget >= kMaxPassBudget) return;
  if (!preqed_call("spvOptimizerRegisterLegalizationPasses")) return;
  spvOptimizerRegisterLegalizationPasses(optimizer);
  pass_budget += 8;
  preqed_result("spvOptimizerRegisterLegalizationPasses", 1);
}
/* ltl: optimizer_lifecycle */
static void call_spvOptimizerRegisterPerformancePasses(payload in) {
  (void)in;
  if (!optimizer || pass_budget >= kMaxPassBudget) return;
  if (!preqed_call("spvOptimizerRegisterPerformancePasses")) return;
  spvOptimizerRegisterPerformancePasses(optimizer);
  pass_budget += 8;
  preqed_result("spvOptimizerRegisterPerformancePasses", 1);
}
/* ltl: optimizer_lifecycle */
static void call_spvOptimizerRegisterSizePasses(payload in) {
  (void)in;
  if (!optimizer || pass_budget >= kMaxPassBudget) return;
  if (!preqed_call("spvOptimizerRegisterSizePasses")) return;
  spvOptimizerRegisterSizePasses(optimizer);
  pass_budget += 8;
  preqed_result("spvOptimizerRegisterSizePasses", 1);
}
/* ltl: optimizer_lifecycle */
static void call_spvOptimizerRegisterPassFromFlag(payload in) {
  if (!optimizer || pass_budget >= kMaxPassBudget) return;
  std::string flag = text_of(in);
  if (!preqed_call("spvOptimizerRegisterPassFromFlag")) return;
  bool ok = spvOptimizerRegisterPassFromFlag(optimizer, flag.c_str());
  preqed_result("spvOptimizerRegisterPassFromFlag", ok);
  if (ok) pass_budget += 1;
}
/* Splits the payload on NUL bytes into at most kMaxFlags NUL-terminated flags. */
static size_t split_flags(payload in, std::string* storage, const char** flags) {
  size_t count = 0;
  size_t start = 0;
  for (size_t i = 0; i <= in.n && count < kMaxFlags; i++) {
    if (i < in.n && in.p[i] != 0) continue;
    storage[count].assign(reinterpret_cast<const char*>(in.p) + start, i - start);
    flags[count] = storage[count].c_str();
    count++;
    start = i + 1;
  }
  return count;
}
/* ltl: optimizer_lifecycle */
static void call_spvOptimizerRegisterPassesFromFlags(payload in) {
  if (!optimizer || pass_budget >= kMaxPassBudget) return;
  std::string storage[kMaxFlags];
  const char* flags[kMaxFlags];
  size_t count = split_flags(in, storage, flags);
  if (!preqed_call("spvOptimizerRegisterPassesFromFlags")) return;
  bool ok = spvOptimizerRegisterPassesFromFlags(optimizer, flags, count);
  preqed_result("spvOptimizerRegisterPassesFromFlags", ok);
  if (ok) pass_budget += static_cast<unsigned>(count);
}
/* ltl: optimizer_lifecycle */
static void call_spvOptimizerRegisterPassesFromFlagsWhilePreservingTheInterface(payload in) {
  if (!optimizer || pass_budget >= kMaxPassBudget) return;
  std::string storage[kMaxFlags];
  const char* flags[kMaxFlags];
  size_t count = split_flags(in, storage, flags);
  if (!preqed_call("spvOptimizerRegisterPassesFromFlagsWhilePreservingTheInterface")) return;
  bool ok = spvOptimizerRegisterPassesFromFlagsWhilePreservingTheInterface(
      optimizer, flags, count);
  preqed_result("spvOptimizerRegisterPassesFromFlagsWhilePreservingTheInterface", ok);
  if (ok) pass_budget += static_cast<unsigned>(count);
}
/* ltl: optimizer_options_lifecycle, optimizer_lifecycle, binary_ownership, no_run_after_failed_run */
static void call_spvOptimizerRun(payload in) {
  if (!optimizer || !optimizer_options || optimized || optimizer_failed) return;
  size_t count = 0;
  const uint32_t* words = words_for(byte(in, 0), kMaxOptWords, &count, rest(in, 1));
  if (!words) return;
  spv_binary out = nullptr;
  /* The optimizer only guarantees valid input: source/opt/ir_context.cpp:1106
   * asserts when a pass walks an OpEntryPoint that is not a function, which is
   * what the pre-validation the caller switched off would have rejected. */
  if (optimizer_skips_validation &&
      (!context || spvValidateBinary(context, words, count, nullptr) != SPV_SUCCESS))
    return;
  if (!preqed_call("spvOptimizerRun")) return;
  spv_result_t result = spvOptimizerRun(optimizer, words, count, &out,
                                        optimizer_options);
  preqed_result("spvOptimizerRun", result == SPV_SUCCESS);
  if (result == SPV_SUCCESS) optimized = out;
  else optimizer_failed = 1;
}

/* ===== C++ API (libspirv.hpp, optimizer.hpp, linker.hpp, linter.hpp) =====
 * Same data flow as the C API above. Each C++ object lives on the heap in one
 * slot, like the C handles, so construction, use and destruction are separate
 * records; LinkerOptions is a plain value object and needs no slot. */

static spvtools::Context* cpp_context;
static spvtools::SpirvTools* cpp_tools;
static spvtools::ValidatorOptions* cpp_validator_options;
static spvtools::OptimizerOptions* cpp_optimizer_options;
static spvtools::ReducerOptions* cpp_reducer_options;
static spvtools::FuzzerOptions* cpp_fuzzer_options;
static spvtools::Optimizer* cpp_optimizer;
static spvtools::Linter* cpp_linter;
static spvtools::LinkerOptions linker_options;
static unsigned cpp_pass_budget;
static int cpp_optimizer_failed;  /* Optimizer::Run returned false: see optimizer_failed */
/* optimizer.hpp CreateAnalyzeLiveInputPass "populates |live_locs| and
 * |live_builtins|", CreateEliminateDeadOutputStoresPass reads them: the passes
 * keep the pointers, so the sets are static and outlive every optimizer. */
static std::unordered_set<uint32_t> live_locs;
static std::unordered_set<uint32_t> live_builtins;
/* Stream for Optimizer::SetPrintAll / SetTimeReport; static for the same reason. */
static std::ostringstream pass_output;

static void cpp_consumer(spv_message_level_t, const char*, const spv_position_t&,
                         const char*) {
  consumer_messages++;
}

/* preqed names are the qualified C++ names; TYPE##_##METHOD names the wrapper. */
#define CPP_NEW(SLOT, TYPE, ARGS)                                   \
  static void call_##TYPE##_new(payload in) {                       \
    (void)in;                                                       \
    if (SLOT) return;                                               \
    if (!preqed_call("spvtools::" #TYPE "::" #TYPE)) return;       \
    SLOT = new spvtools::TYPE ARGS;                                 \
    preqed_result("spvtools::" #TYPE "::" #TYPE, 1);               \
  }
#define CPP_DELETE(SLOT, TYPE)                                      \
  static void call_##TYPE##_delete(payload in) {                    \
    (void)in;                                                       \
    if (!SLOT) return;                                              \
    if (!preqed_call("spvtools::" #TYPE "::~" #TYPE)) return;      \
    delete SLOT;                                                    \
    SLOT = nullptr;                                                 \
    preqed_result("spvtools::" #TYPE "::~" #TYPE, 1);              \
  }
#define CPP_CALL(SLOT, TYPE, METHOD, ARGS)                          \
  static void call_##TYPE##_##METHOD(payload in) {                  \
    (void)in;                                                       \
    if (!SLOT) return;                                              \
    if (!preqed_call("spvtools::" #TYPE "::" #METHOD)) return;     \
    SLOT->METHOD ARGS;                                              \
    preqed_result("spvtools::" #TYPE "::" #METHOD, 1);             \
  }

/* Context */
/* ltl: cpp_context_lifecycle */
CPP_NEW(cpp_context, Context, (env_of(byte(in, 0))))
/* ltl: cpp_context_lifecycle */
CPP_DELETE(cpp_context, Context)
/* ltl: cpp_context_lifecycle */
CPP_CALL(cpp_context, Context, SetMessageConsumer, (cpp_consumer))
/* ltl: cpp_context_lifecycle */
static void call_Context_CContext(payload in) {
  (void)in;
  if (!cpp_context) return;
  if (!preqed_call("spvtools::Context::CContext")) return;
  spv_context& mutable_view = cpp_context->CContext();
  const spv_context& const_view = static_cast<const spvtools::Context*>(cpp_context)->CContext();
  preqed_result("spvtools::Context::CContext", mutable_view && mutable_view == const_view);
}
/* ltl: cpp_context_lifecycle */
static void call_Context_move(payload in) {
  (void)in;
  if (!cpp_context) return;
  if (!preqed_call("spvtools::Context::Context(Context&&)")) return;
  /* "Enables move constructor/assignment operations": the slot ends up holding the moved-to object */
  spvtools::Context* moved = new spvtools::Context(std::move(*cpp_context));
  delete cpp_context;
  cpp_context = moved;
  preqed_result("spvtools::Context::Context(Context&&)", cpp_context->CContext() != nullptr);
}
/* ltl: cpp_context_lifecycle */
static void call_Context_assign(payload in) {
  if (!cpp_context) return;
  if (!preqed_call("spvtools::Context::operator=")) return;
  *cpp_context = spvtools::Context(env_of(byte(in, 0)));
  preqed_result("spvtools::Context::operator=", cpp_context->CContext() != nullptr);
}

/* SpirvTools */
/* ltl: cpp_tools_lifecycle */
CPP_NEW(cpp_tools, SpirvTools, (env_of(byte(in, 0))))
/* ltl: cpp_tools_lifecycle */
CPP_DELETE(cpp_tools, SpirvTools)
/* ltl: cpp_tools_lifecycle */
static void call_SpirvTools_IsValid(payload in) {
  (void)in;
  if (!cpp_tools) return;
  if (!preqed_call("spvtools::SpirvTools::IsValid")) return;
  preqed_result("spvtools::SpirvTools::IsValid", cpp_tools->IsValid());
}
/* ltl: cpp_tools_lifecycle */
static void call_SpirvTools_Parse(payload in) {
  if (!cpp_tools) return;
  size_t count = 0;
  const uint32_t* words = words_for(byte(in, 0), kMaxWords, &count, rest(in, 1));
  if (!words) return;
  std::vector<uint32_t> module(words, words + count);
  if (!preqed_call("spvtools::SpirvTools::Parse")) return;
  /* no diagnostic object: "If diagnostic is null the context's message consumer will be used" */
  bool ok = cpp_tools->Parse(
      module,
      [](const spv_endianness_t, const spv_parsed_header_t&) { return SPV_SUCCESS; },
      [](const spv_parsed_instruction_t& inst) {
        parsed_words += inst.num_words;
        return SPV_SUCCESS;
      });
  preqed_result("spvtools::SpirvTools::Parse", ok);
}
/* ltl: cpp_tools_lifecycle */
static void call_SpirvTools_Validate(payload in) {
  if (!cpp_tools) return;
  size_t count = 0;
  const uint32_t* words = words_for(byte(in, 0), kMaxWords, &count, rest(in, 1));
  if (!words) return;
  if (!preqed_call("spvtools::SpirvTools::Validate")) return;
  /* with the C++ options object when there is one: this is where its setters take effect */
  bool ok = cpp_validator_options ? cpp_tools->Validate(words, count, *cpp_validator_options)
                                  : cpp_tools->Validate(words, count);
  preqed_result("spvtools::SpirvTools::Validate", ok);
}

/* ValidatorOptions */
/* ltl: cpp_validator_options_lifecycle */
CPP_NEW(cpp_validator_options, ValidatorOptions, ())
/* ltl: cpp_validator_options_lifecycle */
CPP_DELETE(cpp_validator_options, ValidatorOptions)
/* the 9 spv_validator_limit values, any non-zero limit */
/* ltl: cpp_validator_options_lifecycle */
CPP_CALL(cpp_validator_options, ValidatorOptions, SetUniversalLimit, (static_cast<spv_validator_limit>(byte(in, 0) % 9), word(in, 1) | 1u))
#define CPP_VALIDATOR_BOOL(METHOD) \
  CPP_CALL(cpp_validator_options, ValidatorOptions, METHOD, ((byte(in, 0) & 1) != 0))
/* ltl: cpp_validator_options_lifecycle */
CPP_VALIDATOR_BOOL(SetRelaxStructStore)
/* ltl: cpp_validator_options_lifecycle */
CPP_VALIDATOR_BOOL(SetRelaxBlockLayout)
/* ltl: cpp_validator_options_lifecycle */
CPP_VALIDATOR_BOOL(SetUniformBufferStandardLayout)
/* ltl: cpp_validator_options_lifecycle */
CPP_VALIDATOR_BOOL(SetScalarBlockLayout)
/* ltl: cpp_validator_options_lifecycle */
CPP_VALIDATOR_BOOL(SetWorkgroupScalarBlockLayout)
/* ltl: cpp_validator_options_lifecycle */
CPP_VALIDATOR_BOOL(SetSkipBlockLayout)
/* ltl: cpp_validator_options_lifecycle */
CPP_VALIDATOR_BOOL(SetAllowLocalSizeId)
/* ltl: cpp_validator_options_lifecycle */
CPP_VALIDATOR_BOOL(SetAllowOffsetTextureOperand)
/* ltl: cpp_validator_options_lifecycle */
CPP_VALIDATOR_BOOL(SetAllowVulkan32BitBitwise)
/* ltl: cpp_validator_options_lifecycle */
CPP_VALIDATOR_BOOL(SetRelaxLogicalPointer)
/* ltl: cpp_validator_options_lifecycle */
CPP_VALIDATOR_BOOL(SetBeforeHlslLegalization)
/* ltl: cpp_validator_options_lifecycle */
CPP_VALIDATOR_BOOL(SetFriendlyNames)
/* size 1..4096, alignment 1..32, as for the C setters */
#define CPP_VALIDATOR_LAYOUT(METHOD) \
  CPP_CALL(cpp_validator_options, ValidatorOptions, METHOD, (1u + word(in, 0) % 4096u, 1u << (byte(in, 0) % 6)))
/* ltl: cpp_validator_options_lifecycle */
CPP_VALIDATOR_LAYOUT(SetBufferDescriptorLayout)
/* ltl: cpp_validator_options_lifecycle */
CPP_VALIDATOR_LAYOUT(SetImageDescriptorLayout)
/* ltl: cpp_validator_options_lifecycle */
CPP_VALIDATOR_LAYOUT(SetSamplerDescriptorLayout)
/* ltl: cpp_validator_options_lifecycle */
CPP_VALIDATOR_LAYOUT(SetTensorDescriptorLayout)

/* OptimizerOptions (the validator stays on: set_run_validator is not called) */
/* ltl: cpp_optimizer_options_lifecycle */
CPP_NEW(cpp_optimizer_options, OptimizerOptions, ())
/* ltl: cpp_optimizer_options_lifecycle */
CPP_DELETE(cpp_optimizer_options, OptimizerOptions)
/* ltl: cpp_optimizer_options_lifecycle */
CPP_CALL(cpp_optimizer_options, OptimizerOptions, set_max_id_bound, (word(in, 0) | 1u))
/* ltl: cpp_optimizer_options_lifecycle */
CPP_CALL(cpp_optimizer_options, OptimizerOptions, set_preserve_bindings, ((byte(in, 0) & 1) != 0))
/* ltl: cpp_optimizer_options_lifecycle */
CPP_CALL(cpp_optimizer_options, OptimizerOptions, set_preserve_spec_constants, ((byte(in, 0) & 1) != 0))

/* ReducerOptions, FuzzerOptions: like the C objects, only created, configured,
 * converted to the C handle and destroyed (the reducer and fuzzer are separate libraries) */
/* ltl: cpp_reducer_options_lifecycle */
CPP_NEW(cpp_reducer_options, ReducerOptions, ())
/* ltl: cpp_reducer_options_lifecycle */
CPP_DELETE(cpp_reducer_options, ReducerOptions)
/* ltl: cpp_reducer_options_lifecycle */
CPP_CALL(cpp_reducer_options, ReducerOptions, set_step_limit, (word(in, 0) % 5000u))
/* ltl: cpp_reducer_options_lifecycle */
CPP_CALL(cpp_reducer_options, ReducerOptions, set_fail_on_validation_error, ((byte(in, 0) & 1) != 0))
/* ltl: cpp_reducer_options_lifecycle */
CPP_CALL(cpp_reducer_options, ReducerOptions, set_target_function, (word(in, 0)))
/* ltl: cpp_reducer_options_lifecycle */
static void call_ReducerOptions_handle(payload in) {
  (void)in;
  if (!cpp_reducer_options) return;
  if (!preqed_call("spvtools::ReducerOptions::operator_spv_reducer_options")) return;
  spv_reducer_options handle = *cpp_reducer_options;
  preqed_result("spvtools::ReducerOptions::operator_spv_reducer_options", handle != nullptr);
}
/* ltl: cpp_fuzzer_options_lifecycle */
CPP_NEW(cpp_fuzzer_options, FuzzerOptions, ())
/* ltl: cpp_fuzzer_options_lifecycle */
CPP_DELETE(cpp_fuzzer_options, FuzzerOptions)
/* ltl: cpp_fuzzer_options_lifecycle */
CPP_CALL(cpp_fuzzer_options, FuzzerOptions, enable_replay_validation, ())
/* ltl: cpp_fuzzer_options_lifecycle */
CPP_CALL(cpp_fuzzer_options, FuzzerOptions, set_random_seed, (word(in, 0)))
/* -100..100; negative counts from the end */
/* ltl: cpp_fuzzer_options_lifecycle */
CPP_CALL(cpp_fuzzer_options, FuzzerOptions, set_replay_range, (static_cast<int32_t>(word(in, 0) % 201u) - 100))
/* ltl: cpp_fuzzer_options_lifecycle */
CPP_CALL(cpp_fuzzer_options, FuzzerOptions, set_shrinker_step_limit, (word(in, 0) % 5000u))
/* ltl: cpp_fuzzer_options_lifecycle */
CPP_CALL(cpp_fuzzer_options, FuzzerOptions, enable_fuzzer_pass_validation, ())
/* ltl: cpp_fuzzer_options_lifecycle */
CPP_CALL(cpp_fuzzer_options, FuzzerOptions, enable_all_passes, ())
/* ltl: cpp_fuzzer_options_lifecycle */
static void call_FuzzerOptions_handle(payload in) {
  (void)in;
  if (!cpp_fuzzer_options) return;
  if (!preqed_call("spvtools::FuzzerOptions::operator_spv_fuzzer_options")) return;
  spv_fuzzer_options handle = *cpp_fuzzer_options;
  preqed_result("spvtools::FuzzerOptions::operator_spv_fuzzer_options", handle != nullptr);
}

/* Optimizer */
/* ltl: cpp_optimizer_lifecycle */
CPP_NEW(cpp_optimizer, Optimizer, (env_of(byte(in, 0))))
/* ltl: cpp_optimizer_lifecycle, no_run_after_failed_run */
static void call_Optimizer_delete(payload in) {
  (void)in;
  if (!cpp_optimizer) return;
  if (!preqed_call("spvtools::Optimizer::~Optimizer")) return;
  delete cpp_optimizer;
  cpp_optimizer = nullptr;
  cpp_pass_budget = 0;
  cpp_optimizer_failed = 0;
  preqed_result("spvtools::Optimizer::~Optimizer", 1);
}
/* "Should be called before calling Run()" */
/* ltl: cpp_optimizer_lifecycle */
CPP_CALL(cpp_optimizer, Optimizer, SetTargetEnv, (env_of(byte(in, 0))))
/* "If |out| is null, then no output is generated" */
/* ltl: cpp_optimizer_lifecycle */
CPP_CALL(cpp_optimizer, Optimizer, SetPrintAll, (byte(in, 0) & 1 ? &pass_output : nullptr))
/* ltl: cpp_optimizer_lifecycle */
CPP_CALL(cpp_optimizer, Optimizer, SetTimeReport, (byte(in, 0) & 1 ? &pass_output : nullptr))
/* ltl: cpp_optimizer_lifecycle */
CPP_CALL(cpp_optimizer, Optimizer, SetValidateAfterAll, ((byte(in, 0) & 1) != 0))
/* ltl: cpp_optimizer_lifecycle, no_run_after_failed_run */
static void call_Optimizer_GetPassNames(payload in) {
  (void)in;
  if (!cpp_optimizer || cpp_optimizer_failed) return;  /* the names of null passes cannot be read */
  if (!preqed_call("spvtools::Optimizer::GetPassNames")) return;
  /* "These strings are valid until the associated pass manager is destroyed": read here, not kept */
  std::vector<const char*> names = cpp_optimizer->GetPassNames();
  bool ok = true;
  for (const char* name : names) ok = ok && name && *name;
  preqed_result("spvtools::Optimizer::GetPassNames", ok);
}
/* One pass per record, counted against kMaxPassBudget like the C registration calls. */
#define CPP_PASS(NAME, ARGS)                                        \
  static void call_##NAME(payload in) {                             \
    (void)in;                                                       \
    if (!cpp_optimizer || cpp_pass_budget >= kMaxPassBudget) return; \
    if (!preqed_call("spvtools::" #NAME)) return;                  \
    cpp_optimizer->RegisterPass(spvtools::NAME ARGS);               \
    cpp_pass_budget++;                                              \
    preqed_result("spvtools::" #NAME, 1);                          \
  }
/* ltl: cpp_optimizer_lifecycle */
CPP_PASS(CreateNullPass, ())
/* ltl: cpp_optimizer_lifecycle */
CPP_PASS(CreatePropagateLineInfoPass, ())
/* ltl: cpp_optimizer_lifecycle */
CPP_PASS(CreateRedundantLineInfoElimPass, ())
/* ltl: cpp_optimizer_lifecycle */
CPP_PASS(CreateEliminateDeadInputComponentsPass, ())
/* ltl: cpp_optimizer_lifecycle */
CPP_PASS(CreateEliminateDeadOutputComponentsPass, ())
/* ltl: cpp_optimizer_lifecycle */
CPP_PASS(CreateInterfaceVariableScalarReplacementPass, ())
/* ltl: cpp_optimizer_lifecycle */
CPP_PASS(CreateAnalyzeLiveInputPass, (&live_locs, &live_builtins))
/* ltl: cpp_optimizer_lifecycle */
CPP_PASS(CreateEliminateDeadOutputStoresPass, (&live_locs, &live_builtins))
/* ltl: cpp_optimizer_lifecycle */
static void call_PassToken_assign(payload in) {
  (void)in;
  if (!cpp_optimizer || cpp_pass_budget >= kMaxPassBudget) return;
  if (!preqed_call("spvtools::Optimizer::PassToken::operator=")) return;
  /* "Tokens can only be moved": a token is replaced by move assignment before it is consumed */
  spvtools::Optimizer::PassToken token = spvtools::CreateNullPass();
  token = spvtools::CreateRedundantLineInfoElimPass();
  cpp_optimizer->RegisterPass(std::move(token));
  cpp_pass_budget++;
  preqed_result("spvtools::Optimizer::PassToken::operator=", 1);
}
/* ltl: cpp_optimizer_lifecycle, no_run_after_failed_run */
static void call_Optimizer_Run(payload in) {
  if (!cpp_optimizer || cpp_optimizer_failed) return;
  size_t count = 0;
  const uint32_t* words = words_for(byte(in, 0), kMaxOptWords, &count, rest(in, 1));
  if (!words) return;
  std::vector<uint32_t> out;
  if (!preqed_call("spvtools::Optimizer::Run")) return;
  /* "By default, the binary is validated before any transforms are performed": true for both overloads here */
  bool ok = cpp_optimizer_options ? cpp_optimizer->Run(words, count, &out, *cpp_optimizer_options)
                                  : cpp_optimizer->Run(words, count, &out);
  preqed_result("spvtools::Optimizer::Run", ok);
  if (!ok) cpp_optimizer_failed = 1;
  pass_output.str(std::string());  /* drop what SetPrintAll / SetTimeReport wrote */
}

/* Linter */
/* ltl: cpp_linter_lifecycle */
CPP_NEW(cpp_linter, Linter, (env_of(byte(in, 0))))
/* ltl: cpp_linter_lifecycle */
CPP_DELETE(cpp_linter, Linter)
/* ltl: cpp_linter_lifecycle */
CPP_CALL(cpp_linter, Linter, SetMessageConsumer, (cpp_consumer))
/* ltl: cpp_linter_lifecycle */
static void call_Linter_Consumer(payload in) {
  (void)in;
  if (!cpp_linter) return;
  if (!preqed_call("spvtools::Linter::Consumer")) return;
  const spvtools::MessageConsumer& consumer = cpp_linter->Consumer();
  preqed_result("spvtools::Linter::Consumer", static_cast<bool>(consumer));
}
/* ltl: cpp_linter_lifecycle */
static void call_Linter_Run(payload in) {
  if (!cpp_linter) return;
  size_t count = 0;
  const uint32_t* words = words_for(byte(in, 0), kMaxOptWords, &count, rest(in, 1));
  if (!words) return;
  /* Like the optimizer, the linter walks the IR of the module and only works on valid input: an undefined id
   * aborts in opt/def_use_manager.cpp:56 (repro2.cpp case 5). Linter::Run does not validate, so the harness does. */
  if (!context || spvValidateBinary(context, words, count, nullptr) != SPV_SUCCESS) return;
  if (!preqed_call("spvtools::Linter::Run")) return;
  bool ok = cpp_linter->Run(words, count);
  preqed_result("spvtools::Linter::Run", ok);
}

/* Linker */

#define LINKER_BOOL(NAME)                                           \
  static void call_LinkerOptions_Set##NAME(payload in) {            \
    if (!preqed_call("spvtools::LinkerOptions::Set" #NAME)) return; \
    linker_options.Set##NAME((byte(in, 0) & 1) != 0);               \
    preqed_result("spvtools::LinkerOptions::Set" #NAME, 1);        \
  }                                                                 \
  static void call_LinkerOptions_Get##NAME(payload in) {            \
    (void)in;                                                       \
    if (!preqed_call("spvtools::LinkerOptions::Get" #NAME)) return; \
    linker_options.Get##NAME();                                     \
    preqed_result("spvtools::LinkerOptions::Get" #NAME, 1);        \
  }
LINKER_BOOL(CreateLibrary)
LINKER_BOOL(VerifyIds)
LINKER_BOOL(AllowPartialLinkage)
LINKER_BOOL(UseHighestVersion)
LINKER_BOOL(AllowPtrTypeMismatch)
LINKER_BOOL(HasFnVarCapabilities)
#undef LINKER_BOOL
/* the two CSV options hold CSV text (source/link/fnvar.cpp ParseCsv), not file names */
#define LINKER_TEXT(NAME)                                           \
  static void call_LinkerOptions_Set##NAME(payload in) {            \
    if (!preqed_call("spvtools::LinkerOptions::Set" #NAME)) return; \
    linker_options.Set##NAME(text_of(in));                          \
    preqed_result("spvtools::LinkerOptions::Set" #NAME, 1);        \
  }                                                                 \
  static void call_LinkerOptions_Get##NAME(payload in) {            \
    (void)in;                                                       \
    if (!preqed_call("spvtools::LinkerOptions::Get" #NAME)) return; \
    linker_options.Get##NAME();                                     \
    preqed_result("spvtools::LinkerOptions::Get" #NAME, 1);        \
  }
LINKER_TEXT(FnVarTargetsCsv)
LINKER_TEXT(FnVarArchitecturesCsv)
#undef LINKER_TEXT
static void call_LinkerOptions_SetInFiles(payload in) {
  /* module names, one per linked binary: the payload split on NUL into 1..kMaxFlags names */
  std::string storage[kMaxFlags];
  const char* names[kMaxFlags];
  size_t count = split_flags(in, storage, names);
  if (!preqed_call("spvtools::LinkerOptions::SetInFiles")) return;
  linker_options.SetInFiles(std::vector<std::string>(storage, storage + count));
  preqed_result("spvtools::LinkerOptions::SetInFiles", 1);
}
static void call_LinkerOptions_GetInFiles(payload in) {
  (void)in;
  if (!preqed_call("spvtools::LinkerOptions::GetInFiles")) return;
  linker_options.GetInFiles();
  preqed_result("spvtools::LinkerOptions::GetInFiles", 1);
}
/* ltl: cpp_context_lifecycle */
static void call_Link(payload in) {
  if (!cpp_context) return;
  /* 1..3 modules; selector bytes 1..3 pick each one like words_for, the payload words follow */
  size_t n = 1 + byte(in, 0) % 3;
  std::vector<std::vector<uint32_t>> modules;
  for (size_t i = 0; i < n; i++) {
    size_t count = 0;
    const uint32_t* words = words_for(byte(in, 1 + i), kMaxOptWords, &count, rest(in, 4));
    /* linker.hpp: "Those binaries do not have to be valid, but they should be at least parseable", with a failure
     * return for unparseable ones. In fact linker.cpp:856 reads the schema word of a module before checking its
     * size, and a parseable module that uses an undefined id aborts in opt/def_use_manager.cpp:56 or dereferences
     * a null type (repro2.cpp cases 1, 2, 4). Only modules that validate in the linking context are passed. */
    if (!words || spvValidateBinary(cpp_context->CContext(), words, count, nullptr) != SPV_SUCCESS) return;
    modules.emplace_back(words, words + count);
  }
  /* With a targets / architectures CSV the linker builds a multitarget module and takes one name per module from
   * in_files (source/link/fnvar.cpp:348 asserts modules.size() == options.GetInFiles().size()). */
  bool multitarget = !linker_options.GetFnVarTargetsCsv().empty() || !linker_options.GetFnVarArchitecturesCsv().empty();
  if (multitarget && linker_options.GetInFiles().size() != n) return;
  std::vector<uint32_t> linked;
  if (!preqed_call("spvtools::Link")) return;
  spv_result_t result;
  if (byte(in, 0) & 128) {
    /* the overload taking parallel arrays */
    std::vector<const uint32_t*> pointers;
    std::vector<size_t> sizes;
    for (const std::vector<uint32_t>& module : modules) {
      pointers.push_back(module.data());
      sizes.push_back(module.size());
    }
    result = spvtools::Link(*cpp_context, pointers.data(), sizes.data(), n, &linked, linker_options);
  } else {
    result = spvtools::Link(*cpp_context, modules, &linked, linker_options);
  }
  preqed_result("spvtools::Link", result == SPV_SUCCESS);
}

#undef CPP_NEW
#undef CPP_DELETE
#undef CPP_CALL
#undef CPP_VALIDATOR_BOOL
#undef CPP_VALIDATOR_LAYOUT
#undef CPP_PASS

/* dispatch */

static void (*const api[])(payload) = {
    call_spvSoftwareVersionString, call_spvSoftwareVersionDetailsString,
    call_spvOperandIsConcrete, call_spvOperandIsConcreteMask,
    call_spvTargetEnvDescription, call_spvParseTargetEnv, call_spvParseVulkanEnv,
    call_spvContextCreate, call_spvContextDestroy,
    call_spvValidatorOptionsCreate, call_spvValidatorOptionsDestroy,
    call_spvValidatorOptionsSetUniversalLimit,
    call_spvValidatorOptionsSetRelaxStoreStruct,
    call_spvValidatorOptionsSetRelaxLogicalPointer,
    call_spvValidatorOptionsSetBeforeHlslLegalization,
    call_spvValidatorOptionsSetRelaxBlockLayout,
    call_spvValidatorOptionsSetUniformBufferStandardLayout,
    call_spvValidatorOptionsSetScalarBlockLayout,
    call_spvValidatorOptionsSetWorkgroupScalarBlockLayout,
    call_spvValidatorOptionsSetSkipBlockLayout,
    call_spvValidatorOptionsSetAllowLocalSizeId,
    call_spvValidatorOptionsSetAllowOffsetTextureOperand,
    call_spvValidatorOptionsSetAllowVulkan32BitBitwise,
    call_spvValidatorOptionsSetFriendlyNames,
    call_spvValidatorOptionsSetBufferDescriptorLayout,
    call_spvValidatorOptionsSetImageDescriptorLayout,
    call_spvValidatorOptionsSetSamplerDescriptorLayout,
    call_spvValidatorOptionsSetTensorDescriptorLayout,
    call_spvOptimizerOptionsCreate, call_spvOptimizerOptionsDestroy,
    call_spvOptimizerOptionsSetRunValidator,
    call_spvOptimizerOptionsSetValidatorOptions,
    call_spvOptimizerOptionsSetMaxIdBound,
    call_spvOptimizerOptionsSetPreserveBindings,
    call_spvOptimizerOptionsSetPreserveSpecConstants,
    call_spvReducerOptionsCreate, call_spvReducerOptionsDestroy,
    call_spvReducerOptionsSetStepLimit,
    call_spvReducerOptionsSetFailOnValidationError,
    call_spvReducerOptionsSetTargetFunction,
    call_spvFuzzerOptionsCreate, call_spvFuzzerOptionsDestroy,
    call_spvFuzzerOptionsEnableReplayValidation,
    call_spvFuzzerOptionsSetRandomSeed, call_spvFuzzerOptionsSetReplayRange,
    call_spvFuzzerOptionsSetShrinkerStepLimit,
    call_spvFuzzerOptionsEnableFuzzerPassValidation,
    call_spvFuzzerOptionsEnableAllPasses,
    call_spvTextToBinary, call_spvTextToBinaryWithOptions, call_spvTextDestroy,
    call_spvBinaryToText, call_spvBinaryDestroy,
    call_spvValidate, call_spvValidateWithOptions, call_spvValidateBinary,
    call_spvDiagnosticCreate, call_spvDiagnosticDestroy, call_spvDiagnosticPrint,
    call_spvOpcodeString, call_spvBinaryParse,
    call_spvOptimizerCreate, call_spvOptimizerDestroy,
    call_spvOptimizerSetMessageConsumer,
    call_spvOptimizerRegisterLegalizationPasses,
    call_spvOptimizerRegisterPerformancePasses,
    call_spvOptimizerRegisterSizePasses, call_spvOptimizerRegisterPassFromFlag,
    call_spvOptimizerRegisterPassesFromFlags,
    call_spvOptimizerRegisterPassesFromFlagsWhilePreservingTheInterface,
    call_spvOptimizerRun,
    /* C++ API */
    call_Context_new, call_Context_delete, call_Context_SetMessageConsumer, call_Context_CContext,
    call_Context_move, call_Context_assign, call_SpirvTools_new, call_SpirvTools_delete,
    call_SpirvTools_IsValid, call_SpirvTools_Parse, call_SpirvTools_Validate,
    call_ValidatorOptions_new, call_ValidatorOptions_delete,
    call_ValidatorOptions_SetUniversalLimit, call_ValidatorOptions_SetRelaxStructStore,
    call_ValidatorOptions_SetRelaxBlockLayout, call_ValidatorOptions_SetUniformBufferStandardLayout,
    call_ValidatorOptions_SetScalarBlockLayout, call_ValidatorOptions_SetWorkgroupScalarBlockLayout,
    call_ValidatorOptions_SetSkipBlockLayout, call_ValidatorOptions_SetAllowLocalSizeId,
    call_ValidatorOptions_SetAllowOffsetTextureOperand,
    call_ValidatorOptions_SetAllowVulkan32BitBitwise, call_ValidatorOptions_SetRelaxLogicalPointer,
    call_ValidatorOptions_SetBeforeHlslLegalization, call_ValidatorOptions_SetFriendlyNames,
    call_ValidatorOptions_SetBufferDescriptorLayout, call_ValidatorOptions_SetImageDescriptorLayout,
    call_ValidatorOptions_SetSamplerDescriptorLayout,
    call_ValidatorOptions_SetTensorDescriptorLayout, call_OptimizerOptions_new,
    call_OptimizerOptions_delete, call_OptimizerOptions_set_max_id_bound,
    call_OptimizerOptions_set_preserve_bindings, call_OptimizerOptions_set_preserve_spec_constants,
    call_ReducerOptions_new, call_ReducerOptions_delete, call_ReducerOptions_set_step_limit,
    call_ReducerOptions_set_fail_on_validation_error, call_ReducerOptions_set_target_function,
    call_ReducerOptions_handle, call_FuzzerOptions_new, call_FuzzerOptions_delete,
    call_FuzzerOptions_enable_replay_validation, call_FuzzerOptions_set_random_seed,
    call_FuzzerOptions_set_replay_range, call_FuzzerOptions_set_shrinker_step_limit,
    call_FuzzerOptions_enable_fuzzer_pass_validation, call_FuzzerOptions_enable_all_passes,
    call_FuzzerOptions_handle, call_Optimizer_new, call_Optimizer_delete,
    call_Optimizer_SetTargetEnv, call_Optimizer_SetPrintAll, call_Optimizer_SetTimeReport,
    call_Optimizer_SetValidateAfterAll, call_Optimizer_GetPassNames, call_CreateNullPass,
    call_CreatePropagateLineInfoPass, call_CreateRedundantLineInfoElimPass,
    call_CreateEliminateDeadInputComponentsPass, call_CreateEliminateDeadOutputComponentsPass,
    call_CreateInterfaceVariableScalarReplacementPass, call_CreateAnalyzeLiveInputPass,
    call_CreateEliminateDeadOutputStoresPass, call_PassToken_assign, call_Optimizer_Run,
    call_Linter_new, call_Linter_delete, call_Linter_SetMessageConsumer, call_Linter_Consumer,
    call_Linter_Run, call_LinkerOptions_SetCreateLibrary, call_LinkerOptions_GetCreateLibrary,
    call_LinkerOptions_SetVerifyIds, call_LinkerOptions_GetVerifyIds,
    call_LinkerOptions_SetAllowPartialLinkage, call_LinkerOptions_GetAllowPartialLinkage,
    call_LinkerOptions_SetUseHighestVersion, call_LinkerOptions_GetUseHighestVersion,
    call_LinkerOptions_SetAllowPtrTypeMismatch, call_LinkerOptions_GetAllowPtrTypeMismatch,
    call_LinkerOptions_SetHasFnVarCapabilities, call_LinkerOptions_GetHasFnVarCapabilities,
    call_LinkerOptions_SetFnVarTargetsCsv, call_LinkerOptions_GetFnVarTargetsCsv,
    call_LinkerOptions_SetFnVarArchitecturesCsv, call_LinkerOptions_GetFnVarArchitecturesCsv,
    call_LinkerOptions_SetInFiles, call_LinkerOptions_GetInFiles, call_Link,
};

#define API_COUNT (sizeof api / sizeof api[0])

static void cleanup(void) {
  delete cpp_optimizer;
  delete cpp_linter;
  delete cpp_tools;
  delete cpp_optimizer_options;
  delete cpp_validator_options;
  delete cpp_reducer_options;
  delete cpp_fuzzer_options;
  delete cpp_context;
  cpp_optimizer = nullptr;
  cpp_linter = nullptr;
  cpp_tools = nullptr;
  cpp_optimizer_options = nullptr;
  cpp_validator_options = nullptr;
  cpp_reducer_options = nullptr;
  cpp_fuzzer_options = nullptr;
  cpp_context = nullptr;
  cpp_pass_budget = 0;
  linker_options = spvtools::LinkerOptions();
  live_locs.clear();
  live_builtins.clear();
  pass_output.str(std::string());
  spvDiagnosticDestroy(diagnostic);
  spvTextDestroy(disassembly);
  spvBinaryDestroy(optimized);
  spvBinaryDestroy(binary);
  spvOptimizerDestroy(optimizer);
  spvOptimizerOptionsDestroy(optimizer_options);
  spvValidatorOptionsDestroy(validator_options);
  spvReducerOptionsDestroy(reducer_options);
  spvFuzzerOptionsDestroy(fuzzer_options);
  spvContextDestroy(context);
  diagnostic = nullptr;
  disassembly = nullptr;
  optimized = nullptr;
  binary = nullptr;
  optimizer = nullptr;
  optimizer_options = nullptr;
  validator_options = nullptr;
  reducer_options = nullptr;
  fuzzer_options = nullptr;
  context = nullptr;
  pass_budget = 0;
  optimizer_skips_validation = 0;
  optimizer_failed = 0;
  cpp_optimizer_failed = 0;
  last_text.clear();
  raw.clear();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  preqed_reset();
  size_t offset = 0;
  while (size - offset >= 3) {
    uint8_t op = data[offset];
    size_t len = size_t(data[offset + 1]) | (size_t(data[offset + 2]) << 8);
    offset += 3;
    if (len > size - offset) break;
    payload in = { data + offset, len };
    api[op % API_COUNT](in);
    offset += len;
  }
  cleanup();
  return 0;
}
