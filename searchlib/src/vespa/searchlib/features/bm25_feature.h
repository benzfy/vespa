// Copyright 2019 Oath Inc. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.

#include <vespa/searchlib/fef/blueprint.h>
#include <vespa/searchlib/fef/featureexecutor.h>

namespace search::features {

/**
 * Executor for the BM25 ranking algorithm over a single index field.
 */
class Bm25Executor : public fef::FeatureExecutor {
private:
    struct QueryTerm {
        fef::TermFieldHandle handle;
        const fef::TermFieldMatchData* tfmd;
        double inverse_doc_freq;
        QueryTerm(fef::TermFieldHandle handle_, double inverse_doc_freq_)
            : handle(handle_),
              tfmd(nullptr),
              inverse_doc_freq(inverse_doc_freq_)
        {}
    };

    using QueryTermVector = std::vector<QueryTerm>;

    QueryTermVector _terms;
    double _avg_field_length;
    double _k1_param; // Determines term frequency saturation characteristics.
    double _b_param;  // Adjusts the effects of the field length of the document matched compared to the average field length.

public:
    Bm25Executor(const fef::FieldInfo& field,
                 const fef::IQueryEnvironment& env);

    void handle_bind_match_data(const fef::MatchData& match_data) override;
    void execute(uint32_t docId) override;
};


/**
 * Blueprint for the BM25 ranking algorithm over a single index field.
 */
class Bm25Blueprint : public fef::Blueprint {
private:
    const fef::FieldInfo* _field;

public:
    Bm25Blueprint();

    void visitDumpFeatures(const fef::IIndexEnvironment& env, fef::IDumpFeatureVisitor& visitor) const override;
    fef::Blueprint::UP createInstance() const override;
    fef::ParameterDescriptions getDescriptions() const override {
        return fef::ParameterDescriptions().desc().indexField(fef::ParameterCollection::ANY);
    }
    bool setup(const fef::IIndexEnvironment& env, const fef::ParameterList& params) override;
    fef::FeatureExecutor& createExecutor(const fef::IQueryEnvironment& env, vespalib::Stash& stash) const override;
};

}
